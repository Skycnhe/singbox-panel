package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type session struct {
	username string
	expire   time.Time
}

type AuthManager struct {
	mu       sync.Mutex
	sessions map[string]session
}

func NewAuthManager() *AuthManager {
	return &AuthManager{sessions: make(map[string]session)}
}

func (a *AuthManager) newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *AuthManager) Login(w http.ResponseWriter, username string) string {
	tok := a.newToken()
	a.mu.Lock()
	a.sessions[tok] = session{username: username, expire: time.Now().Add(24 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "sb_session",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	return tok
}

func (a *AuthManager) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sb_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sb_session", Value: "", Path: "/", MaxAge: -1})
}

func (a *AuthManager) Check(r *http.Request) (string, bool) {
	c, err := r.Cookie("sb_session")
	if err != nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.expire) {
		delete(a.sessions, c.Value)
		return "", false
	}
	return s.username, true
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// authMiddleware：/api/* 需登录；首次登录强制改密期间，除改密接口外一律 403。
func (app *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := app.auth.Check(r); !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "未登录"})
			return
		}
		st := app.store.GetSettings()
		if st.ForceChangePassword && r.URL.Path != "/api/auth/change-password" && r.URL.Path != "/api/auth/logout" && r.URL.Path != "/api/auth/me" {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "首次登录请先修改密码", "code": "password_change_required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
