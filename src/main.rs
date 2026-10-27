//! phare —— mihomo 内核的小型多订阅管理器（纯标准库实现）
//!
//! 设计要点
//! - 每个订阅是一个 profile：保存在 $XDG_CONFIG_HOME/phare/profiles/<别名>/
//!   - meta.yaml : 别名、来源 URL、导入时间、节点统计
//!   - raw.txt   : 订阅原文（base64 解码后的节点列表，便于 diff/排错）
//!   - config.yaml: 由节点列表生成的、可直接喂给内核的完整配置
//! - `apply` 通过 external-controller 热加载（PUT /configs），无需重启服务
//! - 生成的配置里 proxy-groups 使用 `include-all-providers`? 否 —— 直接用
//!   `proxies` 内联，保证切换 profile 时面板不丢节点。
//! - 外部网络请求交给系统 curl（支持环境代理），避免引入 TLS 依赖。

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_MIXED_PORT: u16 = 7890;
const DEFAULT_CONTROLLER: &str = "127.0.0.1:9090";

// ---------------------------------------------------------------------------
// 极简 YAML 输出（只用标量/序列/映射，足够表达 mihomo 配置）
// ---------------------------------------------------------------------------

/// 判断是否需要加引号：含 YAML 特殊字符、首字符敏感、能被解析成别的类型
fn yaml_needs_quote(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let first = s.chars().next().unwrap();
    if matches!(
        first,
        '!' | '&' | '*' | '-' | '?' | ':' | '{' | '}' | '[' | ']' | ',' | '#' | '|' | '>' | '@' | '`' | '"' | '\'' | '%'
    ) {
        return true;
    }
    // 能被 YAML 1.1 解析成非字符串的值
    let lower = s.to_ascii_lowercase();
    if matches!(lower.as_str(), "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~") {
        return true;
    }
    if s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() {
        return true;
    }
    s.chars().any(|c| c.is_whitespace() || ":#{}[],&*!|>'\"%@`\\".contains(c))
}

fn yaml_scalar(s: &str) -> String {
    if yaml_needs_quote(s) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        s.to_string()
    }
}

#[derive(Clone, Debug)]
enum Val {
    Str(String),
    Bool(bool),
    Int(i64),
    /// 字符串序列（块式）
    List(Vec<String>),
    /// 键值映射（块式，值为标量）
    Map(Vec<(String, Val)>),
}

/// 把一行代理写成 YAML flow map：{ k: v, k2: [..], kn: {..} }
fn flow_value(v: &Val, quoted_keys: bool) -> String {
    match v {
        Val::Str(s) => yaml_scalar(s),
        Val::Bool(b) => b.to_string(),
        Val::Int(i) => i.to_string(),
        Val::List(items) => format!("[{}]", items.iter().map(|s| yaml_scalar(s)).collect::<Vec<_>>().join(", ")),
        Val::Map(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}{}: {}", if quoted_keys { "'" } else { "" }, k, flow_value(v, quoted_keys)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn flow_map(pairs: &[(String, Val)]) -> String {
    format!(
        "{{{}}}",
        pairs
            .iter()
            .map(|(k, v)| format!("{}: {}", yaml_scalar(k), flow_value(v, false)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// ---------------------------------------------------------------------------
// 节点解析：vless / hysteria2 / trojan / ss / vmess / anytls(部分)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub(crate) struct Proxy {
    pub kind: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub(crate) fields: Vec<(String, Val)>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let table = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let clean: Vec<u8> = s
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in clean {
        let v = table(c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// 拆 "k1=v1&k2=v2"，值做 pct 解码
fn parse_query(q: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for kv in q.split('&') {
        if kv.is_empty() {
            continue;
        }
        let mut it = kv.splitn(2, '=');
        let k = pct_decode(it.next().unwrap_or(""));
        let v = pct_decode(it.next().unwrap_or(""));
        m.insert(k, v);
    }
    m
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

struct Uri<'a> {
    scheme: &'a str,
    userinfo: &'a str,
    host: &'a str,
    port: Option<u16>,
    query: BTreeMap<String, String>,
    fragment: String,
}

fn parse_uri(line: &str) -> Option<Uri<'_>> {
    let (scheme, rest) = line.split_once("://")?;
    let (body, frag) = match rest.split_once('#') {
        Some((b, f)) => (b, f),
        None => (rest, ""),
    };
    let (body, qs) = match body.split_once('?') {
        Some((b, q)) => (b, q),
        None => (body, ""),
    };
    // 去掉路径部分：hysteria2 常见 "host:35000/?query" 写法，斜杠不能进主机名
    let body = match body.find('/') {
        Some(i) => &body[..i],
        None => body,
    };
    let (userinfo, hostport) = match body.rfind('@') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => ("", body),
    };
    // host:port，兼容 [ipv6]:port
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once("]:") {
            Some((h, p)) => (h, p.parse().ok()),
            None => (stripped.trim_end_matches(']'), None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h, Some(p.parse().unwrap_or(0)))
            }
            _ => (hostport, None),
        }
    };
    Some(Uri {
        scheme,
        userinfo,
        host,
        port,
        query: parse_query(qs),
        fragment: pct_decode(frag),
    })
}

fn q<'a>(u: &'a Uri, key: &str) -> &'a str {
    u.query.get(key).map(|s| s.as_str()).unwrap_or("")
}

fn parse_proxy(line: &str) -> Result<Proxy, String> {
    let u = parse_uri(line).ok_or_else(|| format!("无法解析: {}", &line[..line.len().min(40)]))?;
    let name = if u.fragment.is_empty() {
        format!("{}:{}", u.host, u.port.unwrap_or(443))
    } else {
        u.fragment.clone()
    };
    let mut fields: Vec<(String, Val)> = Vec::new();
    let mut push = |k: &str, v: Val| fields.push((k.to_string(), v));

    let kind = match u.scheme {
        "vless" => {
            let sec = q(&u, "security");
            let net = if q(&u, "type").is_empty() { "tcp" } else { q(&u, "type") };
            push("uuid", Val::Str(pct_decode(u.userinfo)));
            push("udp", Val::Bool(true));
            if matches!(sec, "tls" | "reality" | "xtls") {
                push("tls", Val::Bool(true));
            }
            if !q(&u, "flow").is_empty() {
                push("flow", Val::Str(q(&u, "flow").into()));
            }
            let enc = q(&u, "encryption");
            if !enc.is_empty() && enc != "none" {
                push("encryption", Val::Str(enc.into()));
            }
            let sni = if !q(&u, "sni").is_empty() { q(&u, "sni") } else { q(&u, "host") };
            if !sni.is_empty() {
                push("servername", Val::Str(sni.into()));
            }
            if truthy(q(&u, "insecure")) {
                push("skip-cert-verify", Val::Bool(true));
            }
            if !q(&u, "fp").is_empty() {
                push("client-fingerprint", Val::Str(q(&u, "fp").into()));
            }
            if sec == "reality" {
                let mut r: Vec<(String, Val)> = Vec::new();
                if !q(&u, "pbk").is_empty() {
                    r.push(("public-key".into(), Val::Str(q(&u, "pbk").into())));
                }
                if !q(&u, "sid").is_empty() {
                    r.push(("short-id".into(), Val::Str(q(&u, "sid").into())));
                }
                if !r.is_empty() {
                    push("reality-opts", Val::Map(r));
                }
            }
            match net {
                "ws" => {
                    push("network", Val::Str("ws".into()));
                    let mut w: Vec<(String, Val)> = Vec::new();
                    let path = if q(&u, "path").is_empty() { "/" } else { q(&u, "path") };
                    w.push(("path".into(), Val::Str(path.into())));
                    if !q(&u, "host").is_empty() {
                        w.push((
                            "headers".into(),
                            Val::Map(vec![("Host".into(), Val::Str(q(&u, "host").into()))]),
                        ));
                    }
                    push("ws-opts", Val::Map(w));
                }
                "grpc" => {
                    push("network", Val::Str("grpc".into()));
                    let svc = if !q(&u, "serviceName").is_empty() { q(&u, "serviceName") } else { q(&u, "path") };
                    push(
                        "grpc-opts",
                        Val::Map(vec![("grpc-service-name".into(), Val::Str(svc.into()))]),
                    );
                }
                "h2" => {
                    push("network", Val::Str("h2".into()));
                    let mut h: Vec<(String, Val)> = Vec::new();
                    let path = if q(&u, "path").is_empty() { "/" } else { q(&u, "path") };
                    h.push(("path".into(), Val::Str(path.into())));
                    if !q(&u, "host").is_empty() {
                        h.push(("host".into(), Val::List(vec![q(&u, "host").into()])));
                    }
                    push("h2-opts", Val::Map(h));
                }
                other => push("network", Val::Str(other.into())),
            }
            "vless"
        }
        "hysteria2" | "hy2" => {
            push("password", Val::Str(pct_decode(u.userinfo)));
            push("udp", Val::Bool(true));
            if !q(&u, "sni").is_empty() {
                push("sni", Val::Str(q(&u, "sni").into()));
            }
            if truthy(q(&u, "insecure")) {
                push("skip-cert-verify", Val::Bool(true));
            }
            let obfs = q(&u, "obfs");
            if !obfs.is_empty() && obfs != "none" {
                push("obfs", Val::Str(obfs.into()));
                push("obfs-password", Val::Str(q(&u, "obfs-password").into()));
            }
            if !q(&u, "mport").is_empty() {
                push("ports", Val::Str(q(&u, "mport").into()));
            }
            if !q(&u, "alpn").is_empty() {
                push(
                    "alpn",
                    Val::List(q(&u, "alpn").split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()),
                );
            }
            "hysteria2"
        }
        "trojan" => {
            push("password", Val::Str(pct_decode(u.userinfo)));
            push("udp", Val::Bool(true));
            let sni = if !q(&u, "sni").is_empty() { q(&u, "sni") } else { q(&u, "peer") };
            if !sni.is_empty() {
                push("sni", Val::Str(sni.into()));
            }
            if truthy(q(&u, "allowInsecure")) || truthy(q(&u, "insecure")) {
                push("skip-cert-verify", Val::Bool(true));
            }
            if q(&u, "type") == "ws" {
                push("network", Val::Str("ws".into()));
                let mut w: Vec<(String, Val)> = Vec::new();
                let path = if q(&u, "path").is_empty() { "/" } else { q(&u, "path") };
                w.push(("path".into(), Val::Str(path.into())));
                if !q(&u, "host").is_empty() {
                    w.push((
                        "headers".into(),
                        Val::Map(vec![("Host".into(), Val::Str(q(&u, "host").into()))]),
                    ));
                }
                push("ws-opts", Val::Map(w));
            }
            "trojan"
        }
        "ss" => {
            let (method, password) = match pct_decode(u.userinfo).split_once(':') {
                Some((m, p)) => (m.to_string(), p.to_string()),
                None => ("aes-256-gcm".to_string(), pct_decode(u.userinfo)),
            };
            push("cipher", Val::Str(method));
            push("password", Val::Str(password));
            push("udp", Val::Bool(true));
            "ss"
        }
        "vmess" => {
            // vmess://base64(json)
            let raw = b64_decode(u.host).ok_or("vmess 载荷无法解码")?;
            let json = String::from_utf8_lossy(&raw).to_string();
            let get = |k: &str| -> String {
                // 极简 JSON 取值：找 "k":"v"
                let pat = format!("\"{}\"", k);
                if let Some(i) = json.find(&pat) {
                    let rest = &json[i + pat.len()..];
                    if let Some(c) = rest.find(':') {
                        let after = rest[c + 1..].trim_start();
                        if let Some(s) = after.strip_prefix('"') {
                            if let Some(e) = s.find('"') {
                                return s[..e].to_string();
                            }
                        }
                    }
                }
                String::new()
            };
            let host = {
                let a = get("add");
                if a.is_empty() { u.host.to_string() } else { a }
            };
            let port = get("port").parse().unwrap_or(443);
            push("uuid", Val::Str(get("id")));
            push("alterId", Val::Int(get("aid").parse().unwrap_or(0)));
            push("cipher", Val::Str(if get("scy").is_empty() { "auto".into() } else { get("scy") }));
            push("udp", Val::Bool(true));
            if get("tls").eq_ignore_ascii_case("tls") {
                push("tls", Val::Bool(true));
                let sni = if !get("sni").is_empty() { get("sni") } else { get("host") };
                if !sni.is_empty() {
                    push("servername", Val::Str(sni));
                }
            }
            if get("net") == "ws" {
                push("network", Val::Str("ws".into()));
                let mut w: Vec<(String, Val)> = Vec::new();
                let path = if get("path").is_empty() { "/".into() } else { get("path") };
                w.push(("path".into(), Val::Str(path)));
                if !get("host").is_empty() {
                    w.push((
                        "headers".into(),
                        Val::Map(vec![("Host".into(), Val::Str(get("host")))]),
                    ));
                }
                push("ws-opts", Val::Map(w));
            }
            let n = get("ps");
            return Ok(Proxy {
                kind: "vmess".into(),
                name: if n.is_empty() { name } else { n },
                server: host,
                port,
                fields,
            });
        }
        other => return Err(format!("暂不支持的协议: {other}")),
    };

    let server = if u.host.is_empty() {
        // vmess 已在上面单独返回；此处兜底
        String::new()
    } else {
        u.host.to_string()
    };
    Ok(Proxy {
        kind: kind.into(),
        name,
        server,
        port: u.port.unwrap_or(443),
        fields,
    })
}

/// 把订阅正文（可能 base64，也可能已是明文）解析成节点列表
fn parse_subscription(text: &str) -> (Vec<Proxy>, Vec<String>) {
    let mut body = text.trim().to_string();
    // 判断是否 base64：解码后能出现 "://" 才认为是
    if !body.contains("://") {
        if let Some(raw) = b64_decode(&body) {
            let s = String::from_utf8_lossy(&raw).to_string();
            if s.contains("://") {
                body = s;
            }
        }
    }
    let mut proxies = Vec::new();
    let mut warns = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains("://") {
            continue;
        }
        match parse_proxy(line) {
            Ok(p) => {
                let key = format!("{}|{}|{}", p.name, p.server, p.port);
                if seen.insert(key) {
                    proxies.push(p);
                }
            }
            Err(e) => warns.push(e),
        }
    }
    // 同名去重
    let mut used: HashSet<String> = HashSet::new();
    for p in proxies.iter_mut() {
        let base = p.name.clone();
        let mut n = 1;
        while !used.insert(p.name.clone()) {
            n += 1;
            p.name = format!("{base} ({n})");
        }
    }
    (proxies, warns)
}

// ---------------------------------------------------------------------------
// 配置生成
// ---------------------------------------------------------------------------

pub(crate) struct GenOpts {
    pub mixed_port: u16,
    pub controller: String,
    pub title: String,
}

fn build_config(proxies: &[Proxy], opt: &GenOpts) -> String {
    // 信息类节点（剩余流量/套餐到期）不参与策略组
    let info_kw = ["剩余流量", "套餐到期", "官网", "订阅到期", "到期时间"];
    let is_info = |n: &str| info_kw.iter().any(|k| n.contains(k));
    let mut real: Vec<String> = proxies.iter().filter(|p| !is_info(&p.name)).map(|p| p.name.clone()).collect();
    if real.is_empty() {
        real = proxies.iter().map(|p| p.name.clone()).collect();
    }

    let mut s = String::new();
    s.push_str("# 由 phare 生成，请勿手动编辑；如需改动请修改 gen_tpl 或工具参数\n");
    s.push_str(&format!("mixed-port: {}\n", opt.mixed_port));
    s.push_str("allow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: info\nipv6: false\n");
    s.push_str(&format!("external-controller: {}\n", opt.controller));
    s.push_str("external-ui: ui\n");
    s.push_str("keep-alive-interval: 30\n");
    s.push_str("profile:\n  store-selected: true\n  store-fake-ip: true\n");
    // DNS
    s.push_str("dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n");
    s.push_str("  fake-ip-filter: ['*.lan', '*.local', '+.msftconnecttest.com', '+.msftncsi.com']\n");
    s.push_str("  default-nameserver: [223.5.5.5, 119.29.29.29]\n");
    s.push_str("  nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']\n");
    s.push_str("  proxy-server-nameserver: [223.5.5.5, 119.29.29.29]\n");
    if !opt.title.is_empty() {
        s.push_str(&format!("  nameserver-policy:\n    'geosite:cn': ['https://dns.alidns.com/dns-query', 223.5.5.5]\n"));
    }

    // proxies
    s.push_str("proxies:\n");
    if proxies.is_empty() {
        s.push_str("  []\n");
    }
    for p in proxies {
        let mut row: Vec<(String, Val)> = vec![
            ("name".into(), Val::Str(p.name.clone())),
            ("type".into(), Val::Str(p.kind.clone())),
            ("server".into(), Val::Str(p.server.clone())),
            ("port".into(), Val::Int(p.port as i64)),
        ];
        row.extend(p.fields.iter().cloned());
        s.push_str(&format!("  - {}\n", flow_map(&row)));
    }

    // 策略组
    const TEST_URL: &str = "https://www.gstatic.com/generate_204";
    s.push_str("proxy-groups:\n");
    let mut sel: Vec<String> = vec!["♻️ 自动选择".into(), "🔯 故障转移".into(), "DIRECT".into()];
    sel.extend(real.iter().cloned());
    let g_sel: Vec<(String, Val)> = vec![
        ("name".into(), Val::Str("🚀 节点选择".into())),
        ("type".into(), Val::Str("select".into())),
        ("proxies".into(), Val::List(sel)),
    ];
    s.push_str(&format!("  - {}\n", flow_map(&g_sel)));

    let g_auto: Vec<(String, Val)> = vec![
        ("name".into(), Val::Str("♻️ 自动选择".into())),
        ("type".into(), Val::Str("url-test".into())),
        ("proxies".into(), Val::List(real.clone())),
        ("url".into(), Val::Str(TEST_URL.into())),
        ("interval".into(), Val::Int(600)),
        ("tolerance".into(), Val::Int(50)),
        ("lazy".into(), Val::Bool(true)),
    ];
    s.push_str(&format!("  - {}\n", flow_map(&g_auto)));

    let g_fb: Vec<(String, Val)> = vec![
        ("name".into(), Val::Str("🔯 故障转移".into())),
        ("type".into(), Val::Str("fallback".into())),
        ("proxies".into(), Val::List(real.clone())),
        ("url".into(), Val::Str(TEST_URL.into())),
        ("interval".into(), Val::Int(600)),
        ("lazy".into(), Val::Bool(true)),
    ];
    s.push_str(&format!("  - {}\n", flow_map(&g_fb)));

    let simple = |name: &str, ty: &str, items: &[&str]| -> String {
        let row: Vec<(String, Val)> = vec![
            ("name".into(), Val::Str(name.into())),
            ("type".into(), Val::Str(ty.into())),
            (
                "proxies".into(),
                Val::List(items.iter().map(|x| x.to_string()).collect()),
            ),
        ];
        flow_map(&row)
    };
    s.push_str(&format!("  - {}\n", simple("🌐 全球直连", "select", &["DIRECT", "🚀 节点选择"])));
    s.push_str(&format!("  - {}\n", simple("🛑 广告拦截", "select", &["REJECT", "DIRECT"])));
    s.push_str(&format!(
        "  - {}\n",
        simple("🐟 兜底分流", "select", &["🚀 节点选择", "DIRECT", "🌐 全球直连", "🛑 广告拦截"])
    ));

    // 规则
    s.push_str("rules:\n");
    for r in [
        "DOMAIN-SUFFIX,local,🌐 全球直连",
        "IP-CIDR,127.0.0.0/8,🌐 全球直连,no-resolve",
        "IP-CIDR,10.0.0.0/8,🌐 全球直连,no-resolve",
        "IP-CIDR,172.16.0.0/12,🌐 全球直连,no-resolve",
        "IP-CIDR,192.168.0.0/16,🌐 全球直连,no-resolve",
        "GEOIP,LAN,🌐 全球直连,no-resolve",
        "GEOIP,CN,🌐 全球直连",
        "MATCH,🐟 兜底分流",
    ] {
        s.push_str(&format!("  - {}\n", yaml_scalar(r)));
    }
    s
}

/// 判断订阅正文是否是完整 Clash YAML 配置（含顶层 proxies: 或 proxy-groups:）
fn looks_like_yaml_config(text: &str) -> bool {
    let head: String = text.chars().take(2000).collect();
    if head.trim_start().starts_with("proxies:") || head.trim_start().starts_with("mixed-port:") {
        return true;
    }
    text.lines()
        .take(200)
        .any(|l| matches!(l.trim_end(), "proxies:" | "proxy-groups:" | "mixed-port:" if !l.starts_with(' ')))
}

/// 行级改写：把外部 UI 相关键注释掉。
/// 原因：内核启动时会**同步**下载 external-ui-url，网络不通会让进程在监听端口前退出。
fn sanitize_yaml(cfg: &str) -> String {
    let mut out = String::new();
    for line in cfg.lines() {
        let t = line.trim_start();
        if t.starts_with("external-ui-url:") || t.starts_with("external-ui-name:") {
            out.push_str(&format!("# [phare] 已移除在线 UI 下载（改用本地 ui 目录）：{}\n", t));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 统计 YAML 里的代理数量与类型（够用的朴素扫描）
fn yaml_stats(cfg: &str) -> (usize, String) {
    let mut in_px = false;
    let mut n = 0;
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for line in cfg.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // 顶层键（无缩进）决定是否进入 proxies 区块
        if !line.starts_with(' ') && !line.starts_with('-') {
            in_px = trimmed == "proxies:";
            continue;
        }
        if !in_px {
            continue;
        }
        let t = trimmed;
        // 两种写法都要支持：
        //   flow : - { name: x, type: vless, ... }    （缩进任意，{ 后可带空格）
        //   block: - name: x /   type: vless          （跨行）
        if t.starts_with('-') {
            let rest = t[1..].trim_start();
            if rest.starts_with('{') {
                n += 1;
                if let Some(v) = yaml_field(rest, "type") {
                    *kinds.entry(v).or_insert(0) += 1;
                }
            } else if rest.starts_with("name:") || rest.contains("type:") {
                n += 1;
                if let Some(v) = yaml_field(rest, "type") {
                    *kinds.entry(v).or_insert(0) += 1;
                }
            }
        } else if n > 0 && t.starts_with("type:") {
            // block 式节点的 type 在下一行
            if let Some(v) = yaml_field(t, "type") {
                *kinds.entry(v).or_insert(0) += 1;
            }
        }
    }
    let ks = kinds.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ");
    (n, ks)
}

/// 从一行 flow/block YAML 片段里取字段值（支持单/双引号，值到逗号或行尾为止）
fn yaml_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    let mut from = 0;
    while let Some(idx) = text[from..].find(&needle) {
        let pos = from + idx;
        // 确保是字段边界（前一个字符是 { , 空白）
        let ok = pos == 0
            || matches!(
                text[..pos].chars().last(),
                Some(' ') | Some('{') | Some(',') | Some('-')
            );
        if ok {
            let rest = text[pos + needle.len()..].trim_start();
            let mut chars = rest.chars();
            let value = match chars.next() {
                Some('\'') => {
                    let body = &rest[1..];
                    match body.find('\'') {
                        Some(e) => body[..e].to_string(),
                        None => body.trim_end_matches('}').trim().to_string(),
                    }
                }
                Some('"') => {
                    let body = &rest[1..];
                    match body.find('"') {
                        Some(e) => body[..e].to_string(),
                        None => body.trim_end_matches('}').trim().to_string(),
                    }
                }
                _ => rest
                    .chars()
                    .take_while(|c| *c != ',' && *c != '}' && *c != '\n')
                    .collect::<String>()
                    .trim()
                    .to_string(),
            };
            if !value.is_empty() {
                return Some(value);
            }
        }
        from = pos + needle.len();
    }
    None
}

/// 订阅直接返回 YAML 配置时：原样保存（去掉在线 UI 下载），并校验可用性
fn import_yaml(alias: &str, url: &str, cfg: &str, dir: &Path, force: bool) -> Result<(), String> {
    if dir.exists() && !force {
        return Err(format!("别名 “{alias}” 已存在，如需覆盖请加 --force"));
    }
    let (nodes, kinds) = yaml_stats(cfg);
    let clean = sanitize_yaml(cfg);
    fs::create_dir_all(dir).map_err(|e| io_err("创建 profile 目录", e))?;
    fs::write(dir.join("raw.txt"), cfg.as_bytes()).map_err(|e| io_err("写 raw.txt", e))?;
    fs::write(dir.join("config.yaml"), clean.as_bytes()).map_err(|e| io_err("写 config.yaml", e))?;
    write_meta(&dir.join("meta.yaml"), alias, url, now_ts(), nodes, &format!("yaml {kinds}"))
        .map_err(|e| io_err("写 meta.yaml", e))?;
    println!("✅ 已导入 “{alias}”（服务端返回完整 YAML 配置）：约 {nodes} 个节点");
    if let Ok(out) = Command::new("mihomo")
        .args(["-t", "-d", &dir.to_string_lossy(), "-f", "config.yaml"])
        .output()
    {
        if !out.status.success() {
            let e = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(format!("内核校验配置失败:\n{}", e.lines().last().unwrap_or("")));
        }
    }
    if active_alias().is_none() {
        set_active(alias)?;
        println!("ℹ️  这是第一个配置，已自动设为当前配置");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 路径与状态
// ---------------------------------------------------------------------------

fn home() -> PathBuf {
    env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

/// 程序自身的状态（当前选中哪个 profile 等），遵循 XDG：~/.config/phare
fn state_dir() -> PathBuf {
    if let Ok(x) = env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("phare");
        }
    }
    home().join(".config/phare")
}

/// profile 库（体积较大，属于数据而非配置），遵循 XDG：~/.local/share/phare
fn data_dir() -> PathBuf {
    if let Ok(x) = env::var("XDG_DATA_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("phare");
        }
    }
    home().join(".local/share/phare")
}

fn core_dir() -> PathBuf {
    env::var("PHARE_CORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home().join(".config/mihomo"))
}

fn profiles_dir() -> PathBuf {
    data_dir().join("profiles")
}

fn active_file() -> PathBuf {
    state_dir().join("active")
}

fn io_err(ctx: &str, e: io::Error) -> String {
    format!("{ctx}: {e}")
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn ts_human(ts: i64) -> String {
    // 不引 chrono：用 UTC 粗略换算成 UTC+8，仅用于展示
    let t = ts + 8 * 3600;
    let days = t / 86400;
    let secs = t % 86400;
    // civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// 极简 meta 读写（每行 key=value，value 用 pct 编码避免换行/等号问题）
fn write_meta(path: &Path, alias: &str, url: &str, imported: i64, nodes: usize, kinds: &str) -> io::Result<()> {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"/:@.-_+".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    let body = format!(
        "alias={}\nurl={}\nimported={}\nnodes={}\nkinds={}\n",
        enc(alias),
        enc(url),
        imported,
        nodes,
        kinds
    );
    fs::write(path, body)
}

fn read_meta(path: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(s) = fs::read_to_string(path) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.to_string(), pct_decode(v));
            }
        }
    }
    m
}

pub struct ProfileInfo {
    pub alias: String,
    pub url: String,
    pub imported: i64,
    pub nodes: usize,
    pub kinds: String,
}

fn list_profiles() -> Vec<ProfileInfo> {
    let mut out = Vec::new();
    let dir = profiles_dir();
    let rd = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let m = read_meta(&p.join("meta.yaml"));
        let alias = m.get("alias").cloned().unwrap_or_else(|| {
            p.file_name().unwrap_or_default().to_string_lossy().to_string()
        });
        out.push(ProfileInfo {
            alias,
            url: m.get("url").cloned().unwrap_or_default(),
            imported: m.get("imported").and_then(|v| v.parse().ok()).unwrap_or(0),
            nodes: m.get("nodes").and_then(|v| v.parse().ok()).unwrap_or(0),
            kinds: m.get("kinds").cloned().unwrap_or_default(),
        });
    }
    out.sort_by(|a, b| b.imported.cmp(&a.imported));
    out
}

fn valid_alias(a: &str) -> bool {
    !a.is_empty()
        && a.chars().count() <= 48
        && !a.contains('/')
        && !a.contains('\0')
        && a != "."
        && a != ".."
}

fn active_alias() -> Option<String> {
    fs::read_to_string(active_file()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// 外部交互：订阅拉取 / 内核 API / 服务控制
// ---------------------------------------------------------------------------

/// 依次尝试的 UA。
/// 不少订阅站点按 UA 分流：中性 UA 可能直接 403，或返回与 Clash 客户端不同的格式，
/// 因此先要「分享链接」格式，拿不到再退到 Clash 系 UA（此时通常返回完整 YAML）。
const UA_LIST: &[&str] = &[
    "phare/0.1",
    "clash.meta",
    "clash-verge/v2.0.3",
    "ClashMetaForAndroid/2.10.1.Meta",
];

fn http_get_with_ua(url: &str, ua: &str) -> Result<(u16, String), String> {
    let out = Command::new("curl")
        .args(["-sSL", "--max-time", "120", "-A", ua, "-w", "\n%{http_code}", url])
        .output()
        .map_err(|e| format!("调用 curl 失败: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "下载失败 ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = match text.rsplit_once('\n') {
        Some((b, c)) => (b.to_string(), c.trim().parse::<u16>().unwrap_or(0)),
        None => (text, 0),
    };
    Ok((code, body))
}

/// 判断正文是否「看起来像可用的订阅内容」
fn usable_body(body: &str) -> bool {
    let t = body.trim_start();
    if t.is_empty() || t.starts_with("<!DOCTYPE") || t.starts_with("<html") || t.starts_with('{') {
        return false;
    }
    // 分享链接 / base64 / Clash YAML 三种都算
    if t.contains("://") || looks_like_yaml_config(t) {
        return true;
    }
    t.chars()
        .take(200)
        .all(|c| c.is_ascii_alphanumeric() || "+/=\r\n".contains(c))
}

fn http_get(url: &str) -> Result<String, String> {
    let mut last = String::new();
    for ua in UA_LIST {
        match http_get_with_ua(url, ua) {
            Ok((code, body)) if (200..300).contains(&code) && usable_body(&body) => {
                return Ok(body);
            }
            Ok((code, body)) => {
                last = if body.trim().is_empty() {
                    format!("HTTP {code}")
                } else {
                    format!("HTTP {code}: {}", body.trim().chars().take(120).collect::<String>())
                };
            }
            Err(e) => last = e,
        }
    }
    Err(format!("下载失败（已尝试 {} 种 User-Agent）：{last}", UA_LIST.len()))
}

fn controller_base(override_addr: Option<&str>) -> String {
    if let Some(a) = override_addr {
        return a.trim_start_matches("http://").trim_end_matches('/').to_string();
    }
    if let Ok(a) = env::var("PHARE_CONTROLLER") {
        if !a.is_empty() {
            return a.trim_start_matches("http://").trim_end_matches('/').to_string();
        }
    }
    // 从内核目录的 config.yaml 里读 external-controller
    if let Ok(s) = fs::read_to_string(core_dir().join("config.yaml")) {
        for line in s.lines() {
            let l = line.trim();
            if let Some(v) = l.strip_prefix("external-controller:") {
                let v = v.trim().trim_matches('\'').trim_matches('"');
                if !v.is_empty() {
                    return v.trim_start_matches("http://").trim_end_matches('/').to_string();
                }
            }
        }
    }
    DEFAULT_CONTROLLER.to_string()
}

fn api(method: &str, path: &str, body: Option<&str>, addr: Option<&str>) -> Result<(u16, String), String> {
    let url = format!("http://{}{}", controller_base(addr), path);
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--max-time", "15", "-X", method]);
    if let Some(b) = body {
        cmd.args(["-H", "Content-Type: application/json", "--data-binary", b]);
    }
    cmd.arg("-w").arg("\n%{http_code}").arg(&url);
    cmd.stdin(Stdio::null());
    let out = cmd.output().map_err(|e| format!("调用 curl 失败: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (payload, code) = match text.rsplit_once('\n') {
        Some((p, c)) => (p.to_string(), c.trim().parse::<u16>().unwrap_or(0)),
        None => (String::new(), 0),
    };
    Ok((code, payload))
}

fn core_running(addr: Option<&str>) -> bool {
    matches!(api("GET", "/version", None, addr), Ok((200, _)))
}

fn service_active() -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "mihomo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// 命令实现
// ---------------------------------------------------------------------------

fn cmd_import(url: &str, alias: Option<&str>, mixed_port: Option<u16>, force: bool, addr: Option<&str>) -> Result<(), String> {
    // 别名：显式 --alias 优先，其余在交互终端里提示输入；非交互时报错
    let alias = match alias {
        Some(a) if !a.trim().is_empty() => a.trim().to_string(),
        _ => {
            // 仅当 stdin 是真正的终端时才交互询问（管道/重定向下不能静默拿到空串）
            if is_real_tty() {
                prompt("请输入配置别名（必填）: ")?.trim().to_string()
            } else {
                return Err("导入必须指定别名：请加 --alias <名称>".into());
            }
        }
    };
    if !valid_alias(&alias) {
        return Err(format!("别名不合法: {alias}（不能含 /，长度 ≤ 48）"));
    }
    let dir = profiles_dir().join(&alias);
    if dir.exists() && !force {
        return Err(format!("别名 “{alias}” 已存在，如需覆盖请加 --force"));
    }

    eprintln!("正在拉取订阅…");
    // 订阅链接如果不带协议，拒绝（避免误传别名）
    if !(url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file://")) {
        return Err("订阅地址需以 http(s):// 开头".into());
    }
    let text = if let Some(p) = url.strip_prefix("file://") {
        fs::read_to_string(p).map_err(|e| io_err(p, e))?
    } else {
        http_get(url)?
    };
    if text.trim().is_empty() {
        return Err("订阅内容为空".into());
    }

    // 部分订阅服务端会直接返回完整 Clash YAML 配置
    if looks_like_yaml_config(&text) {
        return import_yaml(&alias, url, &text, &dir, force);
    }
    let (proxies, warns) = parse_subscription(&text);
    if proxies.is_empty() {
        return Err(format!(
            "没有解析出任何节点（可能是 Clash YAML 格式订阅，暂只支持分享链接/base64 列表）{}",
            if warns.is_empty() {
                String::new()
            } else {
                format!("；示例告警: {}", warns[0])
            }
        ));
    }
    let mut kinds = BTreeMap::new();
    for p in &proxies {
        *kinds.entry(p.kind.clone()).or_insert(0usize) += 1;
    }
    let kinds_s: String = kinds.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ");

    let opt = GenOpts {
        mixed_port: mixed_port.unwrap_or(DEFAULT_MIXED_PORT),
        controller: controller_base(addr),
        title: alias.clone(),
    };
    let cfg = build_config(&proxies, &opt);

    fs::create_dir_all(&dir).map_err(|e| io_err("创建 profile 目录", e))?;
    fs::write(dir.join("raw.txt"), text.as_bytes()).map_err(|e| io_err("写 raw.txt", e))?;
    fs::write(dir.join("config.yaml"), cfg.as_bytes()).map_err(|e| io_err("写 config.yaml", e))?;
    write_meta(&dir.join("meta.yaml"), &alias, url, now_ts(), proxies.len(), &kinds_s)
        .map_err(|e| io_err("写 meta.yaml", e))?;

    println!("✅ 已导入 “{alias}”：{} 个节点（{kinds_s}）", proxies.len());
    for w in warns.iter().take(3) {
        eprintln!("   ⚠ {w}");
    }

    // 校验可解析性交给内核
    if let Ok(out) = Command::new("mihomo")
        .args(["-t", "-d", &dir.to_string_lossy(), "-f", "config.yaml"])
        .output()
    {
        if !out.status.success() {
            let e = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(format!("内核校验配置失败:\n{}", e.lines().last().unwrap_or("")));
        }
    }

    // 若是首个 profile，自动设为当前
    if active_alias().is_none() {
        set_active(&alias)?;
        println!("ℹ️  这是第一个配置，已自动设为当前配置");
    } else {
        println!("ℹ️  当前配置未改变，可用 `phare use {alias}` 切换");
    }
    Ok(())
}

fn set_active(alias: &str) -> Result<(), String> {
    let dir = profiles_dir().join(alias);
    if !dir.join("config.yaml").exists() {
        return Err(format!("配置 “{alias}” 不存在"));
    }
    fs::create_dir_all(state_dir()).map_err(|e| io_err("创建状态目录", e))?;
    fs::write(active_file(), alias).map_err(|e| io_err("写 active", e))?;
    Ok(())
}

/// 运行设置键：切换 profile 时这些必须**保留用户当前值**，不能被新 profile 覆盖。
/// 端口、监听地址、DNS、控制器、UI 等都属于"环境"，与订阅内容无关。
const SETTINGS_KEYS: &[&str] = &[
    "mixed-port",
    "port",
    "socks-port",
    "redir-port",
    "tproxy-port",
    "allow-lan",
    "bind-address",
    "lan-allowed-ips",
    "lan-disallowed-ips",
    "authentication",
    "skip-auth-prefixes",
    "mode",
    "log-level",
    "ipv6",
    "external-controller",
    "external-controller-cors",
    "external-ui",
    "external-dns",
    "secret",
    "interface-name",
    "routing-mark",
    "profile",
    "geodata-mode",
    "geo-auto-update",
    "geox-url",
    "tcp-concurrent",
    "find-process-mode",
    "unified-delay",
    "global-client-fingerprint",
    "keep-alive-interval",
    "keep-alive-idle",
    "sniffer",
    "tun",
    "dns",
    "hosts",
];

/// 从一份完整配置里摘出属于「运行设置」的顶层键（含其缩进的子块），按原顺序返回。
fn extract_settings(cfg: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let lines: Vec<&str> = cfg.lines().collect();
    while i < lines.len() {
        let line = lines[i];
        // 顶层键：不以空白开头、不是注释、不是列表项
        let is_top = !line.starts_with(' ')
            && !line.starts_with('-')
            && !line.trim_start().starts_with('#')
            && !line.trim().is_empty();
        if !is_top {
            i += 1;
            continue;
        }
        let key = line.split(':').next().unwrap_or("").trim();
        if !SETTINGS_KEYS.contains(&key) {
            i += 1;
            continue;
        }
        // 收集该键及其所有缩进子行
        out.push(line.to_string());
        i += 1;
        while i < lines.len() {
            let l = lines[i];
            if l.trim().is_empty() {
                i += 1;
                continue;
            }
            if l.starts_with(' ') || l.starts_with("  -") {
                out.push(l.to_string());
                i += 1;
            } else {
                break;
            }
        }
    }
    out
}

/// 把 settings 段落覆盖进新配置：同名顶层键整体替换，其余保留新配置的
fn merge_settings(new_cfg: &str, settings: &[String]) -> String {
    if settings.is_empty() {
        return new_cfg.to_string();
    }
    // 先按顶层键把 settings 分组成 (key, 行块)
    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    for line in settings {
        let key = line.split(':').next().unwrap_or("").trim().to_string();
        match blocks.last_mut() {
            Some((k, b)) if line.starts_with(' ') => {
                let _ = k;
                b.push(line.clone());
            }
            _ => blocks.push((key, vec![line.clone()])),
        }
    }
    let set_keys: HashSet<&str> = blocks.iter().map(|(k, _)| k.as_str()).collect();

    let mut out: Vec<String> = Vec::new();
    let lines: Vec<&str> = new_cfg.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let is_top = !line.starts_with(' ')
            && !line.starts_with('-')
            && !line.trim_start().starts_with('#')
            && !line.trim().is_empty();
        if is_top {
            let key = line.split(':').next().unwrap_or("").trim();
            if set_keys.contains(key) {
                // 跳过新配置里的整个同名块，用用户设置替换
                i += 1;
                while i < lines.len() && (lines[i].starts_with(' ') || lines[i].trim().is_empty()) {
                    if lines[i].trim().is_empty() { i += 1; continue; }
                    i += 1;
                }
                continue;
            }
        }
        out.push(line.to_string());
        i += 1;
    }
    // 把 settings 块插到文件头注释之后
    let mut head: Vec<String> = Vec::new();
    let mut body: Vec<String> = Vec::new();
    for l in out {
        if body.is_empty() && l.trim_start().starts_with('#') {
            head.push(l);
        } else if body.is_empty() && l.trim().is_empty() {
            continue;
        } else {
            body.push(l);
        }
    }
    let mut res: Vec<String> = head;
    for (_, b) in blocks {
        res.extend(b);
    }
    res.extend(body);
    let mut s = res.join("\n");
    s.push('\n');
    s
}

/// 删除某个顶层键及其缩进子块
fn drop_top_key(cfg: &str, key: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let lines: Vec<&str> = cfg.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let is_top = !line.starts_with(' ')
            && !line.starts_with('-')
            && !line.trim_start().starts_with('#')
            && !line.trim().is_empty();
        if is_top && line.split(':').next().unwrap_or("").trim() == key {
            i += 1;
            while i < lines.len() && (lines[i].starts_with(' ') || lines[i].trim().is_empty()) {
                i += 1;
            }
            continue;
        }
        out.push(line.to_string());
        i += 1;
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// 用户设置文件：切换时保存/读取「运行设置」，避免被订阅内容覆盖
fn settings_file() -> PathBuf {
    state_dir().join("settings.yaml")
}

/// 读取当前生效的内核配置，把运行设置存到 settings.yaml
fn capture_settings() -> Result<usize, String> {
    let cur = core_dir().join("config.yaml");
    let cfg = fs::read_to_string(&cur).unwrap_or_default();
    let mut found = extract_settings(&cfg);
    // 旧配置里若没有局域网相关键，补上默认值，确保用户能通过面板改
    let has = |f: &Vec<String>, k: &str| f.iter().any(|l| l.split(':').next().unwrap_or("").trim() == k);
    let has_allow_lan = has(&found, "allow-lan");
    let has_bind = has(&found, "bind-address");
    if !has_allow_lan {
        found.insert(0, "allow-lan: false".to_string());
    }
    if !has_bind {
        found.insert(1, "bind-address: 127.0.0.1".to_string());
    }
    fs::create_dir_all(state_dir()).map_err(|e| io_err("创建状态目录", e))?;
    let body = format!(
        "# phare 运行设置：切换 profile 时会保留这些值，不会被订阅内容覆盖\n# 可直接编辑此文件，下次 use/update 生效\n{}\n",
        found.join("\n")
    );
    fs::write(settings_file(), body).map_err(|e| io_err("写 settings.yaml", e))?;
    Ok(found.len())
}

fn load_settings() -> Vec<String> {
    fs::read_to_string(settings_file())
        .map(|s| extract_settings(&s))
        .unwrap_or_default()
}

/// 内核只允许加载它自己 -d 目录（及其子目录）下的配置文件，
/// 因此切换=把 profile 复制成内核目录里的 config.yaml，再热加载这个文件。
fn install_to_core(src: &Path) -> Result<PathBuf, String> {
    let core = core_dir();
    fs::create_dir_all(&core).map_err(|e| io_err("创建内核目录", e))?;
    let dst = core.join("config.yaml");

    // 关键：把用户当前的「运行设置」合并进来，绝不被订阅内容覆盖
    let profile_cfg = fs::read_to_string(src).map_err(|e| io_err("读取 profile 配置", e))?;
    // settings.yaml 是运行设置唯一权威来源。
    // 注意：不要用「比较 config.yaml 与 settings.yaml 的修改时间」来判断用户是否在面板改过设置——
    // phare use 自己就会写 config.yaml，那样会导致设置被反复"回捕"并固化（端口被污染就是这么来的）。
    let settings = if settings_file().exists() {
        load_settings()
    } else {
        // 首次使用：从现有内核配置捕获一份快照
        let cur = fs::read_to_string(&dst).unwrap_or_default();
        let _ = capture_settings();
        extract_settings(&cur)
    };
    let mut merged = merge_settings(&profile_cfg, &settings);

    // 端口类键强制快照：settings.yaml 里没有的端口键，一律剔除，
    // 防止「订阅自带的 port/socks-port 混进来导致端口漂移」。
    let declared: HashSet<String> = settings
        .iter()
        .filter(|l| !l.starts_with(' '))
        .map(|l| l.split(':').next().unwrap_or("").trim().to_string())
        .collect();
    for k in ["port", "socks-port", "redir-port", "tproxy-port", "mixed-port"] {
        if !declared.contains(k) {
            merged = drop_top_key(&merged, k);
        }
    }

    // 先写临时文件再改名，避免内核读到半个文件
    let tmp = core.join(".config.yaml.phare-tmp");
    fs::write(&tmp, merged.as_bytes()).map_err(|e| io_err("写入内核配置", e))?;
    fs::rename(&tmp, &dst).map_err(|e| io_err("替换内核 config.yaml", e))?;
    Ok(dst)
}

fn cmd_use(alias: &str, no_reload: bool, addr: Option<&str>) -> Result<(), String> {
    let src = profiles_dir().join(alias).join("config.yaml");
    if !src.exists() {
        return Err(format!("配置 “{alias}” 不存在，先执行 `phare list` 查看"));
    }
    let core_cfg = install_to_core(&src)?;
    set_active(alias)?;
    println!("✅ 当前配置已切换为 “{alias}”");
    println!("   已写入内核目录: {}", core_cfg.display());

    if no_reload {
        println!("（已跳过热加载；重启服务后生效）");
        return Ok(());
    }
    if !core_running(addr) {
        println!("ℹ️  内核未在运行，执行 `phare service start` 后即可生效");
        return Ok(());
    }
    let payload = format!("{{\"path\":{}}}", json_str(&core_cfg.to_string_lossy()));
    match api("PUT", "/configs?force=true", Some(&payload), addr) {
        Ok((204, _)) | Ok((200, _)) => {
            println!("🔄 已热加载到内核（无需重启服务）");
            Ok(())
        }
        Ok((code, body)) => Err(format!("热加载失败 (HTTP {code}): {}", body.trim())),
        Err(e) => Err(e),
    }
}

/// 查看/修改「运行设置」（切换 profile 不会丢失）
fn cmd_settings(args: &[String]) -> Result<(), String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("show") => {
            if !settings_file().exists() {
                // 首次：从当前内核配置捕获
                capture_settings()?;
            }
            let body = fs::read_to_string(settings_file()).map_err(|e| io_err("读取设置", e))?;
            println!("{}", body.trim_end());
            println!("\n（文件: {}）", settings_file().display());
            Ok(())
        }
        Some("edit") => {
            if !settings_file().exists() {
                capture_settings()?;
            }
            let editor = env::var("EDITOR").unwrap_or_else(|_| "nano".into());
            let st = Command::new(&editor)
                .arg(settings_file())
                .status()
                .map_err(|e| format!("无法启动编辑器 {editor}: {e}"))?;
            if !st.success() {
                return Err("编辑器退出异常".into());
            }
            println!("已保存。执行 `phare reload` 应用到内核");
            Ok(())
        }
        Some("set") => {
            // phare settings set <键> <值>
            let key = args.get(1).ok_or("用法: phare settings set <键> <值>")?;
            let val = args.get(2).ok_or("用法: phare settings set <键> <值>")?;
            if !SETTINGS_KEYS.contains(&key.as_str()) {
                return Err(format!("不支持的键: {key}（可用: mixed-port / allow-lan / bind-address / mode ...）"));
            }
            if !settings_file().exists() {
                capture_settings()?;
            }
            let body = fs::read_to_string(settings_file()).map_err(|e| io_err("读取设置", e))?;
            let mut lines: Vec<String> = body.lines().map(|l| l.to_string()).collect();
            let new_line = format!("{key}: {val}");
            let mut replaced = false;
            let mut i = 0;
            while i < lines.len() {
                let k = lines[i].split(':').next().unwrap_or("").trim();
                if k == key.as_str() && !lines[i].starts_with(' ') && !lines[i].starts_with('#') {
                    lines[i] = new_line.clone();
                    replaced = true;
                    // 删除该键原有的缩进子块
                    let j = i + 1;
                    while j < lines.len() && (lines[j].starts_with(' ') && !lines[j].trim().is_empty()) {
                        lines.remove(j);
                    }
                    break;
                }
                i += 1;
            }
            if !replaced {
                lines.push(new_line);
            }
            let mut out = lines.join("\n");
            out.push('\n');
            fs::write(settings_file(), out).map_err(|e| io_err("写设置", e))?;
            println!("已设置 {key}: {val}（执行 `phare reload` 生效）");
            Ok(())
        }
        Some("reset") => {
            fs::remove_file(settings_file()).ok();
            println!("已重置设置文件；下次 use 时会从内核当前配置重新捕获");
            Ok(())
        }
        Some(other) => Err(format!("未知子命令: {other}（show / edit / set / reset）")),
    }
}

/// 初始化内核目录：生成默认配置并同步 geo 数据与面板
fn cmd_init(addr: Option<&str>) -> Result<(), String> {
    let core = core_dir();
    fs::create_dir_all(&core).map_err(|e| io_err("创建内核目录", e))?;
    println!("内核目录: {}", core.display());
    match active_alias() {
        Some(a) => {
            let src = profiles_dir().join(&a).join("config.yaml");
            if src.exists() {
                install_to_core(&src)?;
                println!("已写入当前配置 “{a}” 到 {}", core.join("config.yaml").display());
            }
        }
        None => {
            if !core.join("config.yaml").exists() {
                println!("ℹ️  还没有任何配置，导入后执行 `phare use <别名>` 即可");
            }
        }
    }
    // 面板
    let ui = core.join("ui");
    if !ui.exists() {
        println!("⚠️  未发现面板目录 {}（可从一处已有的 ui 目录复制过来）", ui.display());
    }
    let _ = addr;
    Ok(())
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn cmd_reload(addr: Option<&str>) -> Result<(), String> {
    let alias = active_alias().ok_or("还没有当前配置，先 `phare use <别名>`")?;
    cmd_use(&alias, false, addr)
}

fn cmd_list() {
    let items = list_profiles();
    let active = active_alias();
    if items.is_empty() {
        println!("（还没有任何配置）用 `phare import <订阅链接> --alias <名称>` 导入");
        return;
    }
    println!(
        "{:<3}{:<18}{:<20}{:<14}{:<10}",
        "", "别名", "导入时间", "节点", "协议"
    );
    println!("{}", "-".repeat(72));
    for p in &items {
        let mark = if Some(&p.alias) == active.as_ref() { "*" } else { " " };
        let alias = if p.alias.chars().count() > 16 {
            format!("{}…", p.alias.chars().take(15).collect::<String>())
        } else {
            p.alias.clone()
        };
        println!(
            "{:<3}{:<18}{:<20}{:<14}{:<10}",
            mark,
            alias,
            ts_human(p.imported),
            format!("{} 个", p.nodes),
            if p.kinds.is_empty() { "-" } else { &p.kinds }
        );
    }
    println!("\n* 表示当前配置；完整别名用 `phare show <别名>` 查看")
}

fn cmd_show(alias: &str) {
    let dir = profiles_dir().join(alias);
    let m = read_meta(&dir.join("meta.yaml"));
    if m.is_empty() {
        eprintln!("配置 “{alias}” 不存在");
        return;
    }
    let active = active_alias();
    println!("别名    : {alias}{}", if Some(alias.to_string()) == active { "  ← 当前" } else { "" });
    println!("订阅    : {}", m.get("url").cloned().unwrap_or_default());
    println!(
        "导入时间: {}",
        ts_human(m.get("imported").and_then(|v| v.parse().ok()).unwrap_or(0))
    );
    println!("节点数  : {}", m.get("nodes").cloned().unwrap_or_default());
    println!("协议    : {}", m.get("kinds").cloned().unwrap_or_default());
    println!("文件    : {}", dir.join("config.yaml").display());
}

fn cmd_remove(alias: &str, yes: bool) -> Result<(), String> {
    let dir = profiles_dir().join(alias);
    if !dir.exists() {
        return Err(format!("配置 “{alias}” 不存在"));
    }
    if !yes && is_real_tty() {
        let a = prompt(&format!("确认删除 “{alias}”？[y/N] "))?;
        if !matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("已取消");
            return Ok(());
        }
    } else if !yes {
        return Err("非交互环境下删除需加 --yes".into());
    }
    let was_active = active_alias().as_deref() == Some(alias);
    fs::remove_dir_all(&dir).map_err(|e| io_err("删除目录", e))?;
    if was_active {
        let _ = fs::remove_file(active_file());
        println!("⚠️  删除的是当前配置，当前状态已清空，请 `phare use <别名>` 重新选择");
    }
    println!("🗑  已删除 “{alias}”");
    Ok(())
}

fn cmd_status(addr: Option<&str>) -> Result<(), String> {
    let a = controller_base(addr);
    println!("内核目录 : {}", core_dir().display());
    println!("状态目录 : {}", state_dir().display());
    println!("控制接口 : http://{a}");
    println!("用户服务 : {}", if service_active() { "运行中" } else { "未运行" });
    match api("GET", "/version", None, addr) {
        Ok((200, body)) => {
            let ver = body.split("\"version\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap_or("?");
            println!("内核版本 : {ver}");
        }
        _ => {
            println!("内核版本 : (无法连接控制接口)");
            return Ok(());
        }
    }
    let cur = active_alias().unwrap_or_else(|| "-".into());
    println!("当前配置 : {}", cur);

    // 出口节点：顺着「节点选择 -> 自动选择/故障转移」解析到最终代理
    if let Ok((200, body)) = api("GET", "/proxies", None, addr) {
        let now_of = |name: &str| -> Option<String> {
            let pat = format!("{}:{{", json_str(name));
            let i = body.find(&pat)?;
            let seg = &body[i..];
            let k = seg.find("\"now\":\"")?;
            let rest = &seg[k + 7..];
            let e = rest.find('"')?;
            Some(rest[..e].to_string())
        };
        let mut cur = now_of("🚀 节点选择");
        for _ in 0..3 {
            match cur.clone() {
                Some(n) if n == "♻️ 自动选择" || n == "🔯 故障转移" => cur = now_of(&n),
                _ => break,
            }
        }
        if let Some(n) = cur {
            println!("出口节点 : {n}");
        }
    }
    // 订阅流量信息（如果节点名里有）
    let items = list_profiles();
    if let Some(p) = items.iter().find(|p| Some(&p.alias) == active_alias().as_ref()) {
        println!("订阅地址 : {}", p.url);
        println!("节点数量 : {}", p.nodes);
    }
    Ok(())
}

fn cmd_export(alias: &str, out: Option<&Path>) -> Result<(), String> {
    let src = profiles_dir().join(alias).join("config.yaml");
    if !src.exists() {
        return Err(format!("配置 “{alias}” 不存在"));
    }
    let dst = out.map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(format!("{alias}.yaml")));
    fs::copy(&src, &dst).map_err(|e| io_err("导出", e))?;
    println!("已导出到 {}", dst.display());
    Ok(())
}

fn cmd_install_service() -> Result<(), String> {
    // 生成/覆盖用户级 unit，并把内核 -d 指向 state 目录下的 runtime
    let unit_dir = home().join(".config/systemd/user");
    fs::create_dir_all(&unit_dir).map_err(|e| io_err("创建 unit 目录", e))?;
    let unit = unit_dir.join("mihomo.service");
    let content = format!(
        "[Unit]\nDescription=mihomo core (managed by phare)\nAfter=network.target nss-lookup.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/mihomo -d {}\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=default.target\n",
        runtime_dir().display()
    );
    fs::write(&unit, content).map_err(|e| io_err("写 unit", e))?;
    let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
    let st = Command::new("systemctl")
        .args(["--user", "enable", "--now", "mihomo"])
        .status()
        .map_err(|e| format!("systemctl 失败: {e}"))?;
    if !st.success() {
        return Err("启用服务失败".into());
    }
    println!("✅ 已安装并启动用户级服务 mihomo.service（-d {}）", runtime_dir().display());
    Ok(())
}

fn runtime_dir() -> PathBuf {
    state_dir().join("runtime")
}

fn cmd_sync_runtime(addr: Option<&str>) -> Result<(), String> {
    // 把当前 profile 的 config.yaml、geo 数据、ui 同步到运行时目录
    let a = active_alias().ok_or("还没有当前配置")?;
    let src = profiles_dir().join(&a);
    let rt = runtime_dir();
    fs::create_dir_all(&rt).map_err(|e| io_err("创建运行时目录", e))?;
    fs::copy(src.join("config.yaml"), rt.join("config.yaml")).map_err(|e| io_err("复制配置", e))?;
    // geo 数据与 ui 从原内核目录借用（若存在）
    let core = core_dir();
    for f in ["geoip.metadb", "geosite.dat", "country.mmdb"] {
        let p = core.join(f);
        if p.exists() && !rt.join(f).exists() {
            let _ = fs::copy(&p, rt.join(f));
        }
    }
    let ui_src = core.join("ui");
    if ui_src.exists() && !rt.join("ui").exists() {
        let _ = Command::new("cp").args(["-r", &ui_src.to_string_lossy(), &rt.join("ui").to_string_lossy()]).status();
    }
    println!("已同步 “{a}” 到运行时目录 {}", rt.display());
    if core_running(addr) {
        println!("ℹ️  内核正在运行，执行 `phare apply` / 重启服务 使新配置生效");
    }
    Ok(())
}

/// 判断 stdin 是否为真实终端。
/// 用 /proc/self/fd/0 的指向判断：终端是 /dev/pts/N 或 /dev/ttyN。
fn is_real_tty() -> bool {
    match fs::read_link("/proc/self/fd/0") {
        Ok(p) => {
            let s = p.to_string_lossy().to_string();
            s.starts_with("/dev/pts/") || s.starts_with("/dev/tty")
        }
        Err(_) => false,
    }
}

fn prompt(msg: &str) -> Result<String, String> {
    print!("{msg}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).map_err(|e| format!("读取输入失败: {e}"))?;
    Ok(s)
}

fn usage() {
    println!(
        r#"phare {VERSION} —— 轻量多订阅管理器（配合 mihomo 内核）

用法:
  phare import <订阅链接> --alias <别名> [--force] [--port N]
                        导入订阅（别名必填）。支持 http(s) 或 file:// 本地文件
  phare list            列出全部配置（* 为当前）
  phare use <别名>      切换当前配置并热加载
  phare update [别名]   重新拉取订阅并更新（省略别名则更新当前）
  phare reload          用当前配置强制热加载
  phare show <别名>     查看配置详情
  phare remove <别名> [--yes]
                        删除配置
  phare status          查看内核/服务/出口节点状态
  phare export <别名> [-o 文件]
                        导出合并后的 config.yaml
  phare service <start|stop|restart|status>
                        控制用户级 systemd 服务
  phare settings        查看运行设置（切换 profile 不丢失）
  phare settings set <键> <值>   修改设置，如 allow-lan true
  phare settings edit   用 $EDITOR 编辑设置文件
  phare init            初始化内核目录（写入当前配置）
  phare install-service 安装并启动用户级 systemd 服务

环境变量:
  PHARE_CONTROLLER   覆盖控制接口地址，如 127.0.0.1:9090
  PHARE_CORE_DIR     内核目录（默认 ~/.config/mihomo），用于读取 geo/ui 与控制器地址
  XDG_CONFIG_HOME    状态目录根（默认 ~/.config），实际数据在 <根>/phare
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return;
    }
    // 解析全局 --controller
    let mut addr: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--controller" && i + 1 < args.len() {
            addr = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if let Some(v) = args[i].strip_prefix("--controller=") {
            addr = Some(v.to_string());
            i += 1;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    if rest.is_empty() {
        usage();
        return;
    }
    let cmd = rest[0].as_str();
    let flag = |name: &str| rest.iter().any(|a| a == name);
    let opt_val = |name: &str| -> Option<String> {
        rest.iter()
            .position(|a| a == name)
            .and_then(|i| rest.get(i + 1).cloned())
            .or_else(|| {
                rest.iter()
                    .find_map(|a| a.strip_prefix(&format!("{name}=")).map(|s| s.to_string()))
            })
    };
    let positional: Vec<String> = {
        let mut v = Vec::new();
        let mut skip = false;
        for (i, a) in rest.iter().enumerate() {
            if skip {
                skip = false;
                continue;
            }
            if i == 0 {
                continue;
            }
            if a.starts_with("--") {
                if ["--alias", "--port", "-o"].contains(&a.as_str()) {
                    skip = true;
                }
                continue;
            }
            v.push(a.clone());
        }
        v
    };
    let a = addr.as_deref();

    let res: Result<(), String> = match cmd {
        "import" | "add" => {
            match positional.first().cloned() {
                Some(u) => cmd_import(
                    &u,
                    opt_val("--alias").as_deref(),
                    opt_val("--port").and_then(|p| p.parse().ok()),
                    flag("--force"),
                    a,
                ),
                None => Err("用法: phare import <订阅链接> --alias <别名>".into()),
            }
        }
        "list" | "ls" => {
            cmd_list();
            Ok(())
        }
        "use" | "switch" => match positional.first() {
            Some(x) => cmd_use(x, flag("--no-reload"), a),
            None => Err("用法: phare use <别名>".into()),
        },
        "update" => {
            let alias = positional.first().cloned().or_else(active_alias);
            match alias {
                Some(al) => {
                    let dir = profiles_dir().join(&al);
                    let m = read_meta(&dir.join("meta.yaml"));
                    let url = m.get("url").cloned().unwrap_or_default();
                    if url.is_empty() {
                        Err(format!("找不到 “{al}” 的订阅地址，无法更新"))
                    } else {
                        let port = m.get("port").and_then(|v| v.parse().ok());
                        match cmd_import(&url, Some(&al), port, true, a) {
                            Ok(()) => {
                                if active_alias().as_deref() == Some(al.as_str()) {
                                    cmd_reload(a)
                                } else {
                                    println!("ℹ️  “{al}” 不是当前配置，未热加载");
                                    Ok(())
                                }
                            }
                        Err(e) => Err(e),
                        }
                    }
                }
                None => Err("还没有任何配置".into()),
            }
        }
        "reload" => cmd_reload(a),
        "show" => match positional.first() {
            Some(x) => {
                cmd_show(x);
                Ok(())
            }
            None => Err("用法: phare show <别名>".into()),
        },
        "remove" | "rm" => match positional.first() {
            Some(x) => cmd_remove(x, flag("--yes") || flag("-y")),
            None => Err("用法: phare remove <别名> [--yes]".into()),
        },
        "status" | "st" => cmd_status(a),
        "export" => match positional.first() {
            Some(x) => cmd_export(x, opt_val("-o").as_deref().map(Path::new)),
            None => Err("用法: phare export <别名> [-o 文件]".into()),
        },
        "service" => match positional.first().map(|s| s.as_str()) {
            Some(act @ ("start" | "stop" | "restart" | "status")) => {
                match Command::new("systemctl").args(["--user", act, "mihomo"]).status() {
                    Ok(st) if st.success() => Ok(()),
                    Ok(st) => Err(format!("systemctl --user {act} mihomo 失败（{:?}）", st.code())),
                    Err(e) => Err(format!("systemctl 失败: {e}")),
                }
            }
            _ => Err("用法: phare service <start|stop|restart|status>".into()),
        },
        "settings" | "set" => cmd_settings(&positional),
        "init" => cmd_init(a),
        "install-service" => cmd_install_service(),
        "sync" => cmd_sync_runtime(a),
        "version" | "-V" | "--version" => {
            println!("phare {VERSION}");
            Ok(())
        }
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => Err(format!("未知命令: {other}（`phare help` 查看用法）")),
    };
    if let Err(e) = res {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}

