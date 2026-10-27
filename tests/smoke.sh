#!/usr/bin/env bash
# 端到端冒烟测试：使用本地 fixture 与临时目录，不触碰真实订阅与内核服务
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SRC_DIR}/target/release/phare"
FIXTURE="${SRC_DIR}/tests/fixtures/sample-sub.txt"

[[ -x "${BIN}" ]] || { echo "请先 cargo build --release"; exit 1; }
[[ -f "${FIXTURE}" ]] || { echo "缺少 fixture: ${FIXTURE}"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
export XDG_DATA_HOME="${TMP}/data"
export XDG_CONFIG_HOME="${TMP}/config"
export PHARE_CORE_DIR="${TMP}/core"
mkdir -p "${XDG_DATA_HOME}" "${XDG_CONFIG_HOME}" "${PHARE_CORE_DIR}"

pass=0; fail=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail+1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

echo "== 导入"
"${BIN}" import "file://${FIXTURE}" --alias demo >/dev/null 2>&1
check "导入成功并自动设为当前"        '[[ -f "${XDG_DATA_HOME}/phare/profiles/demo/config.yaml" ]]'
check "meta 记录了来源"               'grep -q "file://" "${XDG_DATA_HOME}/phare/profiles/demo/meta.yaml"'
check "首个配置自动 active"           '[[ "$(cat "${XDG_CONFIG_HOME}/phare/active")" == demo ]]'

echo "== 解析正确性"
cfg="${XDG_DATA_HOME}/phare/profiles/demo/config.yaml"
check "4 个节点"                      '[[ "$(sed -n "/^proxies:/,/^proxy-groups:/p" "${cfg}" | grep -c "^  - {name:")" == 4 ]]'
check "hy2 主机名不含斜杠"            '! grep -q "hy2.test.example:" "${cfg}"'
check "reality public-key 已迁移"     'grep -q "public-key: PUBKEY" "${cfg}"'
check "ws Host 头已迁移"              'grep -q "headers: {Host: cdn.test.example}" "${cfg}"'
check "策略组齐全"                    'grep -q "♻️ 自动选择" "${cfg}"'
check "最终规则 MATCH"                'grep -q "MATCH," "${cfg}"'

echo "== 校验与拒绝"
check "内核语法校验"                  'mihomo -t -d "$(dirname "${cfg}")" -f config.yaml'
check "缺别名被拒"                    '! "${BIN}" import "file://${FIXTURE}"'
check "非法别名被拒"                  '! "${BIN}" import "file://${FIXTURE}" --alias "a/b"'
check "重名不加 --force 被拒"          '! "${BIN}" import "file://${FIXTURE}" --alias demo'
check "--force 可覆盖"                '"${BIN}" import "file://${FIXTURE}" --alias demo --force'

echo "== 服务端返回完整 YAML（4 空格缩进 + '{ name:' 写法）"
YAML_FIX="${SRC_DIR}/tests/fixtures/clash-yaml-sub.txt"
"${BIN}" import "file://${YAML_FIX}" --alias yamlsub >/dev/null 2>&1
ycfg="${XDG_DATA_HOME}/phare/profiles/yamlsub/config.yaml"
check "YAML 订阅导入成功"              '[[ -f "${ycfg}" ]]'
check "节点计数正确（4 个，非 0）"       'grep -q "nodes=4" "${XDG_DATA_HOME}/phare/profiles/yamlsub/meta.yaml"'
check "协议统计正确"                   'grep -q "hysteria2:1" "${XDG_DATA_HOME}/phare/profiles/yamlsub/meta.yaml"'
check "保留订阅自带策略组"              'grep -q "机场自带" "${ycfg}"'

echo "== 运行设置不被订阅覆盖"
"${BIN}" settings set allow-lan false >/dev/null 2>&1
"${BIN}" use yamlsub --no-reload >/dev/null 2>&1
check "allow-lan 用我的设置(false)"     'grep -q "^allow-lan: false" "${PHARE_CORE_DIR}/config.yaml"'
"${BIN}" settings set allow-lan true >/dev/null 2>&1
"${BIN}" use yamlsub --no-reload >/dev/null 2>&1
check "allow-lan 用我的设置(true)"      'grep -q "^allow-lan: true" "${PHARE_CORE_DIR}/config.yaml"'

echo "== 订阅自带的端口不得覆盖我的端口设置"
"${BIN}" settings set mixed-port 7890 >/dev/null 2>&1
# fixture 里带 allow-lan/port 等设置，模拟 wd 那种「订阅自带端口」
"${BIN}" use yamlsub --no-reload >/dev/null 2>&1
check "订阅的 bind-address 不生效"      'grep -q "^bind-address: 127.0.0.1" "${PHARE_CORE_DIR}/config.yaml" || ! grep -q "bind-address" "${PHARE_CORE_DIR}/config.yaml"'
check "未声明的 socks-port 被剔除"      '! grep -q "^socks-port:" "${PHARE_CORE_DIR}/config.yaml"'
check "混合端口保持我的值"              'grep -q "^mixed-port: 7890" "${PHARE_CORE_DIR}/config.yaml"'

echo "== 列表与切换"
check "list 含 demo"                 '"${BIN}" list | grep -qF "demo"'
check "show 输出别名"                 '"${BIN}" show demo | grep -q "别名"'
check "export 可导出"                 '"${BIN}" export demo -o "${TMP}/out.yaml" && [[ -s "${TMP}/out.yaml" ]]'
check "use 不存在的配置失败"           '! "${BIN}" use does-not-exist'
check "use demo 写入内核目录"          '"${BIN}" use demo --no-reload && [[ -f "${PHARE_CORE_DIR}/config.yaml" ]]'

echo "== 删除"
check "非交互删除需 --yes"             '! "${BIN}" remove demo'
check "--yes 删除成功"                '"${BIN}" remove demo --yes && [[ ! -d "${XDG_DATA_HOME}/phare/profiles/demo" ]]'
check "删除当前配置后清空 active"       '[[ ! -f "${XDG_CONFIG_HOME}/phare/active" ]]'

echo
if [[ ${fail} -eq 0 ]]; then
    printf '\033[32m全部通过 (%d)\033[0m\n' "${pass}"
else
    printf '\033[31m失败 %d / 共 %d\033[0m\n' "${fail}" $((pass+fail)); exit 1
fi
