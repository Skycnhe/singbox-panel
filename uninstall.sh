#!/usr/bin/env bash
# singbox-panel 一键卸载脚本
#
# 用法（需 root）：
#   bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/uninstall.sh)
#
# 默认删除：systemd 服务、/usr/local/bin/singbox-panel、/usr/local/singbox-panel
# （含面板数据 panel.json 与 sing-box 配置；卸载后入站与用户信息全部清除）
# 保留数据：bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/uninstall.sh) --keep-data
set -e

BIN="/usr/local/bin/singbox-panel"
INSTALL_DIR="/usr/local/singbox-panel"
SERVICE="/etc/systemd/system/singbox-panel.service"

KEEP_DATA=0
[ "${1:-}" = "--keep-data" ] && KEEP_DATA=1

red()   { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }

if [ "$(id -u)" != "0" ]; then
  red "请用 root 运行"
  exit 1
fi

if [ ! -e "$BIN" ] && [ ! -e "$SERVICE" ] && [ ! -d "$INSTALL_DIR" ]; then
  echo "未检测到 singbox-panel 安装，无需卸载。"
  exit 0
fi

# ---- 停服务 ----
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now singbox-panel 2>/dev/null || true
  rm -f "$SERVICE"
  systemctl daemon-reload 2>/dev/null || true
fi

# ---- 删程序与数据 ----
rm -f "$BIN"
if [ "$KEEP_DATA" = "1" ]; then
  green "已保留数据目录：$INSTALL_DIR/data"
else
  rm -rf "$INSTALL_DIR"
fi

echo
green "卸载完成。"
[ "$KEEP_DATA" = "1" ] && echo "  数据保留在：$INSTALL_DIR/data（重装后可继续使用）"
