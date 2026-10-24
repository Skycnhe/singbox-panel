package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

//go:embed web
var webFS embed.FS

type App struct {
	store   *Store
	auth    *AuthManager
	core    *CoreManager
	stats   *StatsCollector
	dataDir string
}

func (app *App) coreRunning() bool {
	running, _, _, _ := app.core.Status()
	return running
}

func (app *App) coreBinPath() string {
	return app.core.binPath
}

// enforceLimit：某入站/客户端触及流量上限时停用并重新应用配置。
func (app *App) enforceLimit(inboundID, clientID string) {
	changed := false
	if clientID == "" {
		_ = app.store.mutateInbound(inboundID, func(in *Inbound) error {
			if in.Enabled {
				in.Enabled = false
				changed = true
			}
			return nil
		})
	} else {
		_ = app.store.mutateInbound(inboundID, func(in *Inbound) error {
			for i := range in.Clients {
				if in.Clients[i].ID == clientID && in.Clients[i].Enabled {
					in.Clients[i].Enabled = false
					changed = true
				}
			}
			return nil
		})
	}
	if !changed {
		return
	}
	st := app.store.GetSettings()
	cfg, err := buildConfig(st, app.store.ListInbounds())
	if err != nil {
		return
	}
	if err := app.core.WriteConfig(cfg); err != nil {
		return
	}
	if _, err := app.core.Check(); err != nil {
		return
	}
	if app.coreRunning() {
		_ = app.core.Restart()
	}
}

func main() {
	portFlag := flag.Int("port", 0, "面板监听端口（默认 54321，设置页修改后需重启面板生效）")
	dataFlag := flag.String("data", "data", "数据目录")
	flag.Parse()

	store, err := NewStore(*dataFlag)
	if err != nil {
		log.Fatalf("初始化数据目录失败: %v", err)
	}
	st := store.GetSettings()
	app := &App{
		store:   store,
		auth:    NewAuthManager(),
		dataDir: *dataFlag,
	}
	app.core = NewCoreManager(*dataFlag, resolveBinPath(st, *dataFlag))
	app.stats = NewStatsCollector(app)
	stop := make(chan struct{})
	go app.stats.Run(stop)

	// 面板退出时顺带停掉 sing-box 子进程，避免孤儿进程继续占端口
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = app.core.Stop()
		close(stop)
		os.Exit(0)
	}()

	mux := http.NewServeMux()

	// 公开接口
	mux.HandleFunc("/api/auth/login", app.handleLogin)
	mux.HandleFunc("/sub/", app.handleSubscription)

	// 需登录接口
	api := http.NewServeMux()
	api.HandleFunc("/api/auth/me", app.handleMe)
	api.HandleFunc("/api/auth/logout", app.handleLogout)
	api.HandleFunc("/api/auth/change-password", app.handleChangePassword)
	api.HandleFunc("/api/dashboard", app.handleDashboard)
	api.HandleFunc("/api/inbounds", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			app.handleListInbounds(w, r)
		case "POST":
			app.handleCreateInbound(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	api.HandleFunc("/api/inbounds/", app.inboundRouter)
	api.HandleFunc("/api/core/status", app.handleCoreStatus)
	api.HandleFunc("/api/core/logs", app.handleCoreLogs)
	api.HandleFunc("/api/core/apply", app.handleApply)
	api.HandleFunc("/api/core/start", app.handleCoreStart)
	api.HandleFunc("/api/core/stop", app.handleCoreStop)
	api.HandleFunc("/api/core/restart", app.handleCoreRestart)
	api.HandleFunc("/api/core/download", app.handleCoreDownload)
	api.HandleFunc("/api/utils/reality-keypair", app.handleRealityKeypair)
	api.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			app.handleGetSettings(w, r)
		case "PUT":
			app.handleUpdateSettings(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	api.HandleFunc("/api/stats", app.handleStats)
	mux.Handle("/api/", app.authMiddleware(api))

	// 前端静态文件
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("内嵌前端失败: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webSub)))

	port := *portFlag
	if port == 0 {
		port = st.PanelPort
	}
	if port == 443 || strings.Contains(fmt.Sprintf("%d", port), "443") {
		log.Fatalf("面板端口 %d 含 443，拒绝启动", port)
	}
	addr := fmt.Sprintf(":%d", port)
	log.Printf("singbox-panel 启动: http://0.0.0.0%s/ 默认账号 admin/admin（首次登录强制改密）", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("面板启动失败: %v", err)
	}
}

// inboundRouter：/api/inbounds/{id} 与 /api/inbounds/{id}/clients[/...] 路由。
func (app *App) inboundRouter(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
	parts := strings.Split(rest, "/")
	if len(parts) >= 2 && parts[1] == "clients" {
		switch {
		case len(parts) == 2 && r.Method == "POST":
			app.handleCreateClient(w, r)
		case len(parts) == 3 && r.Method == "PUT":
			app.handleUpdateClient(w, r)
		case len(parts) == 3 && r.Method == "DELETE":
			app.handleDeleteClient(w, r)
		case len(parts) == 4 && parts[3] == "link" && r.Method == "GET":
			app.handleClientLink(w, r)
		default:
			http.Error(w, "not found", 404)
		}
		return
	}
	switch r.Method {
	case "PUT":
		app.handleUpdateInbound(w, r)
	case "DELETE":
		app.handleDeleteInbound(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
