#!/usr/bin/env bash
# singbox-panel 一键安装脚本（从源码构建 + systemd 安装）
#
# 用法（需 root）：
#   bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/install.sh)
#
# 行为：
#   1. 检查/安装 Go（已有 Go >= 1.25 则直接复用，否则下载官方 Go 1.25.1 到 /usr/local/go）
#   2. 拉取 Hk001 分支源码并编译，安装二进制到 /usr/local/bin/singbox-panel
#   3. 数据目录 /usr/local/singbox-panel/data；有 systemd 时注册并开机自启服务
#   4. 重复执行 = 升级：重新构建并重启服务（面板数据与 sing-box 配置保留）
# 卸载见 README「卸载」一节。
set -e

REPO="Skycnhe/singbox-panel"
BRANCH="Hk001"
GO_VERSION="1.25.1"
INSTALL_DIR="/usr/local/singbox-panel"
BIN="/usr/local/bin/singbox-panel"
SERVICE="/etc/systemd/system/singbox-panel.service"
PANEL_PORT="54321"

red()   { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
yellow(){ echo -e "\033[33m$*\033[0m"; }

if [ "$(id -u)" != "0" ]; then
  red "请用 root 运行：sudo bash <(curl -Ls https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh)"
  exit 1
fi

command -v curl >/dev/null 2>&1 || { red "缺少 curl，请先安装 curl"; exit 1; }

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  GO_ARCH="amd64" ;;
  aarch64) GO_ARCH="arm64" ;;
  *) red "不支持的架构：$ARCH（仅支持 x86_64 / aarch64）"; exit 1 ;;
esac

# ---- Go ----
go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  ver="$(go version | awk '{print $3}' | sed 's/^go//')"
  # 比较主次版本 >= 1.25
  major="${ver%%.*}"; rest="${ver#*.}"; minor="${rest%%.*}"
  [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 25 ]; }
}
if go_ok; then
  green "Go 已就绪：$(go version)"
else
  yellow "正在安装 Go $GO_VERSION ..."
  tmp_go="/tmp/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  curl -Ls "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$tmp_go"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmp_go"
  rm -f "$tmp_go"
  export PATH="/usr/local/go/bin:$PATH"
  green "Go 已安装：$(go version)"
fi
export PATH="/usr/local/go/bin:$PATH"

# ---- 拉取源码 ----
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
if command -v git >/dev/null 2>&1; then
  git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$BUILD_DIR/src"
else
  curl -Ls "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" -o "$BUILD_DIR/src.tar.gz"
  mkdir -p "$BUILD_DIR/src"
  tar -xzf "$BUILD_DIR/src.tar.gz" -C "$BUILD_DIR/src" --strip-components=1
fi

# ---- 编译安装 ----
mkdir -p "$INSTALL_DIR/data"
if systemctl is-active --quiet singbox-panel 2>/dev/null; then
  systemctl stop singbox-panel || true
fi
cd "$BUILD_DIR/src"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" .
chmod +x "$BIN"
green "二进制已安装：$BIN"

# ---- systemd 服务（systemd 未作为 init 运行时跳过，打印手动运行方式） ----
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  cat > "$SERVICE" <<EOF
[Unit]
Description=sing-box panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN -port $PANEL_PORT -data $INSTALL_DIR/data
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now singbox-panel
  sleep 2
  if systemctl is-active --quiet singbox-panel; then
    green "服务已启动：singbox-panel"
  else
    red "服务启动失败，查看日志：journalctl -u singbox-panel -n 50"
    exit 1
  fi
else
  yellow "未检测到 systemd，服务未注册，请手动运行："
  echo "  $BIN -port $PANEL_PORT -data $INSTALL_DIR/data"
fi

# ---- 完成信息 ----
IP="$(curl -s --max-time 5 ifconfig.me || true)"
if [ -z "$IP" ]; then
  IP="<服务器 IP>"
elif [ "${IP#*:}" != "$IP" ]; then
  IP="[$IP]"  # IPv6 需加方括号
fi
echo
green "安装完成！"
echo "  面板地址：http://$IP:$PANEL_PORT/"
echo "  默认账号：admin / admin（首次登录强制改密）"
echo "  下一步：登录后在设置页下载 sing-box 内核 → 添加入站与客户端 → 应用配置并重启核心"
echo "  服务管理：systemctl {status|restart|stop} singbox-panel"
echo "  一键卸载：bash <(curl -Ls https://raw.githubusercontent.com/$REPO/$BRANCH/uninstall.sh)"
