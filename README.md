# sing-box 面板

一个类似 x-ui 的轻量代理面板：Go 单二进制，前端原生 HTML/CSS/JS（无构建步骤，`go:embed` 内嵌），内核为外部 sing-box 进程。面板负责生成 sing-box 配置、管理核心启停、查看日志、统计流量。

## 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/install.sh)
```

需 root 运行。脚本会：检查/安装 Go（已有 Go >= 1.25 直接复用，否则下载官方 Go 1.25.1）→ 拉取 Hk001 分支源码并编译 → 安装二进制到 `/usr/local/bin/singbox-panel`、数据目录 `/usr/local/singbox-panel/data` → 注册 systemd 服务并开机自启。装完打开 `http://<服务器 IP>:54321/`，默认账号 `admin / admin`（首次登录强制改密），然后在设置页下载 sing-box 内核即可使用。重复执行该命令即为升级（面板数据与 sing-box 配置保留）。

### 卸载

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/uninstall.sh)
```

默认删除服务、二进制与整个 `/usr/local/singbox-panel`（含面板数据与 sing-box 配置）。只删程序、保留数据可用：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Skycnhe/singbox-panel/Hk001/uninstall.sh) --keep-data
```

## 功能清单

- **登录鉴权**：用户名/密码（bcrypt 存哈希），session cookie；默认账号 `admin/admin`，首次登录强制改密（改密前其他 API 一律 403）
- **仪表盘**：sing-box 运行状态（pid/运行时长/版本）、系统信息（CPU/内存/磁盘/负载，读 `/proc`）、总流量、入站与客户端数量
- **入站管理（CRUD）**：协议 VLESS / VMess / Trojan / Shadowsocks / Hysteria2；传输 TCP / WS / gRPC / HTTPUpgrade；TLS（证书路径）与 Reality（面板可自动生成 X25519 密钥对与 short ID）；端口、备注、流量限额（超限自动停用并重新应用配置）
- **客户端管理**：每入站下挂多个客户端（UUID/口令自动生成），生成客户端链接（vless://、vmess://、trojan://、ss://、hysteria2://）与二维码（前端内嵌 qrcode-generator，不依赖后端图片库）
- **订阅**：`/sub/<token>`（token 按客户端生成），默认返回该用户的 sing-box JSON 配置；`?format=links` 返回链接列表
- **流量统计**：优先 v2ray statsService（见“已知限制”），不可用时退化为 clash API 连接快照差分聚合（按入站/用户），界面与 `/api/stats` 注明当前口径；不编造数据，无流量时显示 0
- **内核管理**：按入站/用户生成 `data/singbox/config.json`；启动、停止、重启；查看运行日志（最近 3000 行环形缓冲）；配置变更后一键应用：先 `sing-box check` 校验，失败拒绝应用并回显错误；通过后启动并做 1.5 秒存活复核（check 查不出的初始化错误也能捕获）
- **设置页**：订阅域名、sing-box 二进制路径/版本（支持从 GitHub releases 下载指定版本或最新版）、clash/v2ray API 端口、流量统计来源、登录密码修改
- **安全默认值**：面板默认监听 **54321**；任何入站端口都拒绝 443 及任何含 `443` 的端口（如 8443、1443）；数据存本地 JSON 文件（`data/panel.json`，读写锁 + 原子重命名写入），无 cgo，可静态编译

## 编译

```bash
# 需要 Go 1.22+
go build -o singbox-panel .
```

## 运行

```bash
./singbox-panel -port 54321 -data ./data
# 打开 http://<服务器 IP>:54321/，默认账号 admin / admin（首次登录强制改密）
```

参数：

- `-port`：面板监听端口（默认 54321；设置页改端口需重启面板生效）
- `-data`：数据目录（默认 `./data`，含 `panel.json`、`singbox/config.json`、`certs/`、`bin/`）

首次运行流程：下载 sing-box（设置页填版本下载，或手动把二进制放到 `data/bin/sing-box`）→ 添加入站与客户端 → 点「应用配置并重启核心」。

## systemd 安装

```ini
# /etc/systemd/system/singbox-panel.service
[Unit]
Description=sing-box panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/singbox-panel
ExecStart=/opt/singbox-panel/singbox-panel -port 54321 -data /opt/singbox-panel/data
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now singbox-panel
```

## 已知限制

- **v2ray stats API**：官方 release 二进制默认**不含** v2ray_api（需 `-tags with_v2ray_api` 自编译），因此面板默认关闭该选项；开启后 `sing-box check` 会直接报错，面板会如实回显。默认流量口径为 clash API 聚合。
- **流量口径**：clash 聚合按连接快照差分累计（5 秒一采），核心重启后已累计值保留在面板数据库中；v2ray 口径为累计值，核心重启计数归零时面板只保留历史最大值不回退。
- **Shadowsocks 单口令**：实测 sing-box 1.14 的 shadowsocks 入站不接受 `users` 数组（报 `missing psk`），因此 SS 入站为入站级单口令，仅首个启用客户端的口令真正生效；2022-blake3 系列口令由面板按规范生成 base64 定长密钥（aes-128 用 16 字节，其余 32 字节）。
- **sing-box 版本适配**：生成配置已按 sing-box 1.14 实测修正（新 DNS 格式、无 dns 出站、DNS detour 不指向 direct）。更老版本（<1.12）的 DNS 字段可能不兼容。
- **Hysteria2**：自签模式（`self`）由面板自动生成 10 年期自签证书；生产建议使用真实证书（`tls` 类型填证书路径）。
- **Trojan/VLESS 等无 TLS 时**：链接中 `security=none`，请自行评估明文风险。
- **面板端口修改**：设置页不提供在线改面板端口，改端口需用 `-port` 重启面板。
