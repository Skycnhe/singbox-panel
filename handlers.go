package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func ok(w http.ResponseWriter, data any) {
	writeJSON(w, 200, map[string]any{"ok": true, "data": data})
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
}

// ---------- 认证 ----------

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	st := app.store.GetSettings()
	if req.Username != st.AdminUser || !checkPassword(st.AdminPassHash, req.Password) {
		fail(w, 401, fmt.Errorf("用户名或密码错误"))
		return
	}
	app.auth.Login(w, req.Username)
	ok(w, map[string]any{"force_change": st.ForceChangePassword})
}

func (app *App) handleMe(w http.ResponseWriter, r *http.Request) {
	st := app.store.GetSettings()
	ok(w, map[string]any{
		"username":     st.AdminUser,
		"force_change": st.ForceChangePassword,
	})
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	app.auth.Logout(w, r)
	ok(w, nil)
}

func (app *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	if len(req.NewPassword) < 6 {
		fail(w, 400, fmt.Errorf("新密码至少 6 位"))
		return
	}
	st := app.store.GetSettings()
	if !st.ForceChangePassword && !checkPassword(st.AdminPassHash, req.OldPassword) {
		fail(w, 401, fmt.Errorf("旧密码错误"))
		return
	}
	hash, err := hashPassword(req.NewPassword)
	if err != nil {
		fail(w, 500, err)
		return
	}
	_ = app.store.UpdateSettings(func(s *Settings) error {
		s.AdminPassHash = hash
		s.ForceChangePassword = false
		return nil
	})
	ok(w, nil)
}

// ---------- 仪表盘 ----------

func (app *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	version := app.core.Version()
	running, pid, uptime, _ := app.core.Status()
	inbounds := app.store.ListInbounds()
	var totalUp, totalDown int64
	enabledIn, totalClients := 0, 0
	for _, in := range inbounds {
		totalUp += in.Up
		totalDown += in.Down
		if in.Enabled {
			enabledIn++
		}
		totalClients += len(in.Clients)
	}
	ok(w, map[string]any{
		"core": map[string]any{
			"running": running, "pid": pid,
			"uptime_seconds": int64(uptime.Seconds()),
			"version":        version,
			"config_path":    app.core.ConfigPath(),
		},
		"system":        GetSystemInfo(),
		"traffic":       map[string]any{"up": totalUp, "down": totalDown, "source": app.stats.Source()},
		"inbound_count": enabledIn,
		"inbound_total": len(inbounds),
		"client_count":  totalClients,
	})
}

// ---------- 入站 ----------

func (app *App) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	ok(w, app.store.ListInbounds())
}

func (app *App) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	var in Inbound
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.ID = ""
	in.Tag = ""
	in.Clients = nil
	if err := app.prepareInboundTLS(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := app.store.AddInbound(&in); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, in)
}

func (app *App) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
	id = strings.Split(id, "/")[0]
	var in Inbound
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	old, found := app.store.FindInbound(id)
	if !found {
		fail(w, 404, fmt.Errorf("入站不存在"))
		return
	}
	in.ID = id
	in.Tag = old.Tag
	if err := app.prepareInboundTLS(&in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := app.store.UpdateInbound(&in); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, in)
}

func (app *App) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
	if err := app.store.DeleteInbound(id); err != nil {
		fail(w, 404, err)
		return
	}
	ok(w, nil)
}

// prepareInboundTLS：Reality 缺密钥时自动生成；hysteria2 自签缺证书时自动生成。
func (app *App) prepareInboundTLS(in *Inbound) error {
	if in.TLSEnabled && in.TLSType == "reality" {
		if in.RealityPriv == "" {
			priv, pub, err := genRealityKeypair()
			if err != nil {
				return err
			}
			in.RealityPriv, in.RealityPub = priv, pub
		}
		if in.RealitySID == "" {
			in.RealitySID = randomHex(4)
		}
		if in.RealityDest == "" {
			in.RealityDest = "www.microsoft.com:443"
		}
	}
	if in.Protocol == "hysteria2" && in.TLSType == "self" {
		certDir := app.dataDir + "/certs"
		name := "hy2-" + firstNonEmpty(in.ID, "new")
		if in.CertPath == "" || in.KeyPath == "" {
			cert, key, err := genSelfSignedCert(certDir, name, firstNonEmpty(in.ServerName, "localhost"))
			if err != nil {
				return err
			}
			in.CertPath, in.KeyPath = cert, key
		}
		in.TLSEnabled = true
	}
	return nil
}

// ---------- 客户端 ----------

func (app *App) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/inbounds/"), "/")
	if len(parts) < 2 {
		fail(w, 400, fmt.Errorf("路径错误"))
		return
	}
	inboundID := parts[0]
	var c Client
	if err := readJSON(r, &c); err != nil {
		fail(w, 400, err)
		return
	}
	if err := app.store.AddClient(inboundID, &c); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, c)
}

func (app *App) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/inbounds/"), "/")
	if len(parts) < 3 {
		fail(w, 400, fmt.Errorf("路径错误"))
		return
	}
	var c Client
	if err := readJSON(r, &c); err != nil {
		fail(w, 400, err)
		return
	}
	if err := app.store.UpdateClient(parts[0], parts[2], c); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, c)
}

func (app *App) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/inbounds/"), "/")
	if len(parts) < 3 {
		fail(w, 400, fmt.Errorf("路径错误"))
		return
	}
	if err := app.store.DeleteClient(parts[0], parts[2]); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, nil)
}

// handleClientLink 返回某客户端的链接与订阅地址。
func (app *App) handleClientLink(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/inbounds/"), "/")
	if len(parts) < 3 {
		fail(w, 400, fmt.Errorf("路径错误"))
		return
	}
	in, found := app.store.FindInbound(parts[0])
	if !found {
		fail(w, 404, fmt.Errorf("入站不存在"))
		return
	}
	for _, c := range in.Clients {
		if c.ID == parts[2] {
			host := hostForLinks(app.store.GetSettings(), r.Host)
			link, err := buildClientLink(in, c, host)
			if err != nil {
				fail(w, 400, err)
				return
			}
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			subURL := fmt.Sprintf("%s://%s/sub/%s", scheme, r.Host, c.Token)
			ok(w, map[string]any{"link": link, "sub_url": subURL, "token": c.Token})
			return
		}
	}
	fail(w, 404, fmt.Errorf("客户端不存在"))
}

// ---------- 订阅（公开接口，凭 token） ----------

func (app *App) handleSubscription(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	token = strings.Split(token, "/")[0]
	c, in, found := app.store.FindClientByToken(token)
	if !found || !c.Enabled || !in.Enabled {
		http.Error(w, "订阅不存在或已停用", 404)
		return
	}
	host := hostForLinks(app.store.GetSettings(), r.Host)
	if r.URL.Query().Get("format") == "links" {
		link, err := buildClientLink(in, c, host)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(link + "\n"))
		return
	}
	cfg, err := buildSubConfig(in, c, host)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="singbox.json"`)
	_ = json.NewEncoder(w).Encode(cfg)
}

// ---------- 内核 ----------

func (app *App) handleCoreStatus(w http.ResponseWriter, r *http.Request) {
	version := app.core.Version()
	running, pid, uptime, _ := app.core.Status()
	ok(w, map[string]any{
		"running": running, "pid": pid,
		"uptime_seconds": int64(uptime.Seconds()),
		"version":        version,
		"bin_path":       app.coreBinPath(),
		"config_path":    app.core.ConfigPath(),
	})
}

func (app *App) handleCoreLogs(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	ok(w, map[string]any{"logs": app.core.Logs(lines)})
}

// handleApply：生成配置 → sing-box check 校验 → 校验失败拒绝应用并回显错误 → 通过则重启核心。
func (app *App) handleApply(w http.ResponseWriter, r *http.Request) {
	st := app.store.GetSettings()
	cfg, err := buildConfig(st, app.store.ListInbounds())
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := app.core.WriteConfig(cfg); err != nil {
		fail(w, 500, err)
		return
	}
	out, err := app.core.Check()
	if err != nil {
		fail(w, 400, fmt.Errorf("sing-box 配置校验失败，已拒绝应用:\n%s", out))
		return
	}
	running, _, _, _ := app.core.Status()
	if running {
		if err := app.core.Restart(); err != nil {
			fail(w, 500, err)
			return
		}
	} else {
		if err := app.core.Start(); err != nil {
			fail(w, 500, err)
			return
		}
	}
	// check 只能发现配置解码错误（如缺 PSK 这类初始化错误查不出），
	// 因此启动后等 1.5 秒确认进程仍存活，否则把日志回显为应用失败。
	time.Sleep(1500 * time.Millisecond)
	if alive, _, _, _ := app.core.Status(); !alive {
		logs := app.core.Logs(15)
		fail(w, 500, fmt.Errorf("sing-box 启动后退出，应用失败，日志:\n%s", strings.Join(logs, "\n")))
		return
	}
	ok(w, map[string]any{"check_output": out})
}

func (app *App) handleCoreStart(w http.ResponseWriter, r *http.Request) {
	if err := app.core.Start(); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, nil)
}

func (app *App) handleCoreStop(w http.ResponseWriter, r *http.Request) {
	if err := app.core.Stop(); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, nil)
}

func (app *App) handleCoreRestart(w http.ResponseWriter, r *http.Request) {
	if err := app.core.Restart(); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, nil)
}

func (app *App) handleCoreDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	_ = readJSON(r, &req)
	path, err := DownloadSingbox(app.dataDir, req.Version)
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = app.store.UpdateSettings(func(s *Settings) error {
		s.SingboxPath = path
		return nil
	})
	app.core.SetBinPath(path)
	ok(w, map[string]any{"path": path, "version": app.core.Version()})
}

func (app *App) handleRealityKeypair(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := genRealityKeypair()
	if err != nil {
		fail(w, 500, err)
		return
	}
	ok(w, map[string]any{"private_key": priv, "public_key": pub})
}

// ---------- 设置 ----------

func (app *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	st := app.store.GetSettings()
	ok(w, map[string]any{
		"panel_port":       st.PanelPort,
		"sub_domain":       st.SubDomain,
		"singbox_path":     st.SingboxPath,
		"singbox_version":  st.SingboxVersion,
		"clash_port":       st.ClashPort,
		"v2ray_port":       st.V2RayPort,
		"enable_v2ray_api": st.EnableV2RayAPI,
		"stats_source":     st.StatsSource,
		"admin_user":       st.AdminUser,
		"stats_actual":     app.stats.Source(),
		"core_version":     app.core.Version(),
	})
}

func (app *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubDomain      string `json:"sub_domain"`
		SingboxPath    string `json:"singbox_path"`
		ClashPort      int    `json:"clash_port"`
		V2RayPort      int    `json:"v2ray_port"`
		EnableV2RayAPI bool   `json:"enable_v2ray_api"`
		StatsSource    string `json:"stats_source"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	if req.StatsSource != "auto" && req.StatsSource != "v2ray" && req.StatsSource != "clash" {
		fail(w, 400, fmt.Errorf("stats_source 只能是 auto/v2ray/clash"))
		return
	}
	st := app.store.GetSettings()
	if req.ClashPort != 0 {
		if err := validPort(req.ClashPort, st.PanelPort, 0, 0); err != nil {
			fail(w, 400, err)
			return
		}
	}
	if req.V2RayPort != 0 {
		if err := validPort(req.V2RayPort, st.PanelPort, 0, 0); err != nil {
			fail(w, 400, err)
			return
		}
	}
	_ = app.store.UpdateSettings(func(s *Settings) error {
		s.SubDomain = req.SubDomain
		if req.SingboxPath != "" {
			s.SingboxPath = req.SingboxPath
			app.core.SetBinPath(req.SingboxPath)
		}
		if req.ClashPort != 0 {
			s.ClashPort = req.ClashPort
		}
		if req.V2RayPort != 0 {
			s.V2RayPort = req.V2RayPort
		}
		s.EnableV2RayAPI = req.EnableV2RayAPI
		s.StatsSource = req.StatsSource
		return nil
	})
	ok(w, nil)
}

// ---------- 流量 ----------

func (app *App) handleStats(w http.ResponseWriter, r *http.Request) {
	inbounds := app.store.ListInbounds()
	var totalUp, totalDown int64
	for _, in := range inbounds {
		totalUp += in.Up
		totalDown += in.Down
	}
	ok(w, map[string]any{
		"source":     app.stats.Source(),
		"note":       "流量口径：优先 v2ray statsService 累计值；不可用时退化为 clash API 连接快照差分聚合（按入站/用户）。核心重启后 v2ray 计数归零，面板只保留历史最大值不回退。",
		"total_up":   totalUp,
		"total_down": totalDown,
		"inbounds":   inbounds,
	})
}
