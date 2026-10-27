#!/usr/bin/env bash
# phare 安装脚本
#   ./install.sh            编译并安装到 ~/.local/bin，可选初始化内核目录
#   ./install.sh --uninstall 卸载（保留 ~/.local/share/phare 中的配置数据）
#
# 不修改任何需要 root 权限的路径。
set -euo pipefail

APP="phare"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DST="${HOME}/.local/bin/${APP}"
DATA_DIR="${HOME}/.local/share/phare"
CONFIG_DIR="${HOME}/.config/phare"
CORE_DIR="${HOME}/.config/mihomo"
UNIT="${HOME}/.config/systemd/user/mihomo.service"

info() { printf '\033[32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

uninstall() {
    info "卸载 ${APP}"
    systemctl --user disable --now mihomo.service 2>/dev/null || true
    rm -f "${BIN_DST}"
    rm -f "${UNIT}"
    systemctl --user daemon-reload 2>/dev/null || true
    warn "已保留配置数据: ${DATA_DIR} 与 ${CONFIG_DIR}"
    warn "如需彻底清理（含订阅凭据），手动执行: rm -rf '${DATA_DIR}' '${CONFIG_DIR}'"
    info "卸载完成"
}

if [[ "${1:-}" == "--uninstall" || "${1:-}" == "-u" ]]; then
    uninstall
    exit 0
fi

# ---------------------------------------------------------------- 依赖检查
info "检查依赖"
command -v cargo >/dev/null || die "未找到 cargo，请先安装 Rust 工具链（https://rustup.rs）"
command -v mihomo >/dev/null || die "未找到 mihomo 内核，请先安装（如 sudo apt install mihomo）"
command -v curl >/dev/null || die "未找到 curl"

# ---------------------------------------------------------------- 编译
info "编译 ${APP}（release）"
cd "${SRC_DIR}"
cargo build --release --quiet
BIN_SRC="${SRC_DIR}/target/release/${APP}"
[[ -x "${BIN_SRC}" ]] || die "编译产物不存在: ${BIN_SRC}"

# ---------------------------------------------------------------- 安装二进制
info "安装到 ${BIN_DST}"
mkdir -p "$(dirname "${BIN_DST}")"
install -m 0755 "${BIN_SRC}" "${BIN_DST}"

case ":${PATH}:" in
    *":${HOME}/.local/bin:"*) ;;
    *) warn "${HOME}/.local/bin 不在 PATH 中，请把下面这行加入 ~/.bashrc:"
       warn "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# ---------------------------------------------------------------- 目录
info "准备目录"
mkdir -p "${DATA_DIR}/profiles" "${CONFIG_DIR}"

# ---------------------------------------------------------------- geo 数据（可选，从内核目录借用）
for f in geoip.metadb geosite.dat country.mmdb; do
    if [[ -f "${CORE_DIR}/${f}" ]]; then
        info "发现 ${CORE_DIR}/${f}（内核目录已有，无需重复下载）"
        break
    fi
done

# ---------------------------------------------------------------- 服务
if [[ -x /usr/bin/mihomo ]]; then
    if systemctl --user list-unit-files 2>/dev/null | grep -q '^mihomo.service'; then
        info "检测到用户级服务 mihomo.service"
        if ! systemctl --user is-active --quiet mihomo.service; then
            info "启动 mihomo.service"
            systemctl --user start mihomo.service || warn "启动失败，请查看 journalctl --user -u mihomo"
        fi
    else
        warn "尚未安装用户级服务，可执行: ${APP} install-service"
    fi
else
    warn "mihomo 不在 /usr/bin 下，稍后请手动调整服务定义"
fi

# ---------------------------------------------------------------- 自检
info "自检"
"${BIN_DST}" version
"${BIN_DST}" list || true

cat <<EOF

$(info "安装完成")

  命令: ${BIN_DST}
  程序数据: ${DATA_DIR}
  当前选择: ${CONFIG_DIR}/active
  内核目录: ${CORE_DIR}

常用:
  phare import <订阅链接> --alias <别名>   # 导入（别名必填）
  phare list                              # 列出全部
  phare use <别名>                        # 切换并热加载
  phare update [别名]                     # 重新拉取订阅
  phare status                            # 查看状态/出口节点
  phare service restart                   # 重启内核服务
EOF
