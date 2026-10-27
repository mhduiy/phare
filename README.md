# phare

一个用 Rust 写的、配合 **mihomo** 内核使用的轻量多订阅管理器 —— 用来替代 Clash Verge 那种"粘贴链接就生成配置"的体验。

名字取自 Beacon（灯塔），取"照着船指引方向"的意思。二进制只有 ~750 KB，**零第三方 crate**，只用标准库。

## 为什么不用 mihomo 自带的订阅功能

mihomo 内核本身**没有订阅管理**：`proxy-providers` 只能拉回节点列表，不会生成策略组和规则，换一家机场还是得手写 YAML。phare 补的就是这一层。

## 安装

```bash
cd ~/Dev/portmux
./install.sh              # 编译 + 安装到 ~/.local/bin + 启动服务
./install.sh --uninstall  # 卸载（保留配置数据）
```

依赖：`cargo`（Rust 工具链）、`mihomo`、`curl`。全部安装在用户目录下，**不需要 sudo**。

## 目录布局

| 路径 | 内容 |
|---|---|
| `~/.local/bin/phare` | 程序本体 |
| `~/.local/share/phare/profiles/<别名>/` | profile 库：`config.yaml`、`raw.txt`（订阅原文）、`meta.yaml` |
| `~/.config/phare/active` | 当前选中哪个 profile |
| `~/.config/mihomo/` | 内核工作目录：`config.yaml`（当前 profile 的副本）、`ui/`、geo 数据 |
| `~/.config/systemd/user/mihomo.service` | 用户级服务，开机自启 |

> **为什么内核配置要复制一份到 `~/.config/mihomo/`**：mihomo 只允许热加载**自己 `-d` 目录及其子目录**下的文件，软链接也会被解析真实路径后拒绝。所以 `phare use` 会把 profile 复制进内核目录再热加载。

## 用法

```bash
phare import <订阅链接> --alias <别名>   # 导入（别名必填），支持 http(s):// 和 file://
phare import <链接> --alias <别名> --force  # 覆盖同名
phare list                              # 列出全部，* 为当前
phare use <别名>                        # 切换并热加载，无需重启服务
phare update [别名]                     # 重新拉取订阅（默认当前）
phare reload                            # 强制热加载当前配置
phare show <别名>                       # 详情
phare remove <别名> --yes               # 删除
phare status                            # 内核/服务/出口节点/当前配置
phare export <别名> -o out.yaml          # 导出配置
phare service <start|stop|restart|status>  # 控制服务
phare init                              # 初始化内核目录
phare install-service                   # 安装用户级 systemd 服务
```

## 支持的订阅格式

- **分享链接列表**（各种 base64 或明文）：`vless://`、`hysteria2://`、`trojan://`、`ss://`、`vmess://`
- **完整 Clash YAML 配置**：服务端若直接返回 YAML，则原样采纳，并自动移除 `external-ui-url`
  （该键会让内核启动时**同步**下载面板，网络不通时进程会在监听端口前退出）

## 环境变量

| 变量 | 作用 |
|---|---|
| `PHARE_CONTROLLER` | 覆盖控制接口，如 `127.0.0.1:9090` |
| `PHARE_CORE_DIR` | 内核目录，默认 `~/.config/mihomo` |
| `XDG_DATA_HOME` / `XDG_CONFIG_HOME` | 遵循 XDG 标准重定向数据/配置目录 |

## 开发

```bash
cargo build --release
cargo test                 # 无第三方依赖，单元测试用本地 fixture
./tests/smoke.sh           # 端到端冒烟测试（不触碰真实订阅）
```
