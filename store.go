package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ---------- 数据模型 ----------

type Settings struct {
	PanelPort           int    `json:"panel_port"`
	SubDomain           string `json:"sub_domain"` // 订阅/链接里的域名或 IP，空则用请求 Host
	SingboxPath         string `json:"singbox_path"`
	SingboxVersion      string `json:"singbox_version"`
	ClashPort           int    `json:"clash_port"`
	ClashSecret         string `json:"clash_secret"`
	V2RayPort           int    `json:"v2ray_port"`
	EnableV2RayAPI      bool   `json:"enable_v2ray_api"`
	StatsSource         string `json:"stats_source"` // auto | v2ray | clash
	AdminUser           string `json:"admin_user"`
	AdminPassHash       string `json:"admin_pass_hash"`
	ForceChangePassword bool   `json:"force_change_password"`
}

type Client struct {
	ID           string  `json:"id"`
	InboundID    string  `json:"inbound_id"`
	Name         string  `json:"name"`
	UUID         string  `json:"uuid"`     // vless/vmess 用；trojan/ss/hysteria2 可为空
	Password     string  `json:"password"` // trojan/ss/hysteria2 用
	Flow         string  `json:"flow"`     // vless flow，如 xtls-rprx-vision
	Token        string  `json:"token"`    // 订阅 token
	Up           int64   `json:"up"`
	Down         int64   `json:"down"`
	TotalLimitGB float64 `json:"total_limit_gb"` // 0 = 不限
	Enabled      bool    `json:"enabled"`
	CreatedAt    int64   `json:"created_at"`
}

type Inbound struct {
	ID           string   `json:"id"`
	Tag          string   `json:"tag"`      // sing-box 里的 tag：in-<id>
	Protocol     string   `json:"protocol"` // vless|vmess|trojan|shadowsocks|hysteria2
	Remark       string   `json:"remark"`
	Port         int      `json:"port"`
	Listen       string   `json:"listen"`
	Enabled      bool     `json:"enabled"`
	Transport    string   `json:"transport"` // tcp|ws|grpc|httpupgrade
	WSPath       string   `json:"ws_path"`
	WSHost       string   `json:"ws_host"`
	GRPCService  string   `json:"grpc_service"`
	HUPath       string   `json:"hu_path"`
	HUHost       string   `json:"hu_host"`
	TLSEnabled   bool     `json:"tls_enabled"`
	TLSType      string   `json:"tls_type"` // tls|reality|self
	CertPath     string   `json:"cert_path"`
	KeyPath      string   `json:"key_path"`
	ServerName   string   `json:"server_name"` // SNI
	RealityPriv  string   `json:"reality_private_key"`
	RealityPub   string   `json:"reality_public_key"`
	RealitySID   string   `json:"reality_short_id"`
	RealityDest  string   `json:"reality_dest"` // 如 www.microsoft.com:443（仅作握手目标，非监听端口）
	RealitySNIs  []string `json:"reality_server_names"`
	SSMethod     string   `json:"ss_method"`
	SSPassword   string   `json:"ss_password"` // 非 2022 加密时入站级口令（取首个客户端口令）
	Up           int64    `json:"up"`
	Down         int64    `json:"down"`
	TotalLimitGB float64  `json:"total_limit_gb"` // 0 = 不限
	CreatedAt    int64    `json:"created_at"`
	Clients      []Client `json:"clients"`
}

type DB struct {
	Settings Settings  `json:"settings"`
	Inbounds []Inbound `json:"inbounds"`
}

type Store struct {
	mu   sync.RWMutex
	dir  string
	path string
	db   DB
}

// ---------- 工具 ----------

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// validPort 校验端口：范围、绝不含 443 子串、不与面板/统计端口冲突。
func validPort(p, panelPort, clashPort, v2rayPort int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("端口 %d 超出范围 1-65535", p)
	}
	if strings.Contains(strconv.Itoa(p), "443") {
		return fmt.Errorf("端口 %d 含 443，面板禁止使用任何含 443 的端口", p)
	}
	if p == panelPort || p == clashPort || p == v2rayPort {
		return fmt.Errorf("端口 %d 与面板/统计端口冲突", p)
	}
	return nil
}

var protocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true,
	"shadowsocks": true, "hysteria2": true,
}

var transports = map[string]bool{
	"tcp": true, "ws": true, "grpc": true, "httpupgrade": true,
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
}

// ---------- 存储 ----------

func defaultSettings() Settings {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	return Settings{
		PanelPort:           54321,
		SingboxPath:         "",
		ClashPort:           19090,
		ClashSecret:         newToken(),
		V2RayPort:           18080,
		EnableV2RayAPI:      false, // 官方 release 二进制默认不含 v2ray_api（需 -tags with_v2ray_api 自编译），默认关闭以保证 check 通过
		StatsSource:         "auto",
		AdminUser:           "admin",
		AdminPassHash:       string(hash),
		ForceChangePassword: true,
	}
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "singbox"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "certs"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, path: filepath.Join(dir, "panel.json")}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.db = DB{Settings: defaultSettings()}
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.db); err != nil {
		return nil, fmt.Errorf("panel.json 解析失败: %w", err)
	}
	// 补齐缺失的默认值（老数据兼容）
	if s.db.Settings.PanelPort == 0 {
		s.db.Settings.PanelPort = 54321
	}
	if s.db.Settings.ClashPort == 0 {
		s.db.Settings.ClashPort = 19090
	}
	if s.db.Settings.V2RayPort == 0 {
		s.db.Settings.V2RayPort = 18080
	}
	if s.db.Settings.ClashSecret == "" {
		s.db.Settings.ClashSecret = newToken()
	}
	if s.db.Settings.StatsSource == "" {
		s.db.Settings.StatsSource = "auto"
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) GetSettings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db.Settings
}

func (s *Store) UpdateSettings(fn func(*Settings) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.db.Settings); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) ListInbounds() []Inbound {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Inbound, len(s.db.Inbounds))
	copy(out, s.db.Inbounds)
	return out
}

func (s *Store) FindInbound(id string) (Inbound, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, in := range s.db.Inbounds {
		if in.ID == id {
			return in, true
		}
	}
	return Inbound{}, false
}

// mutateInbound 在写锁内对某个入站做修改并保存。
func (s *Store) mutateInbound(id string, fn func(*Inbound) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.db.Inbounds {
		if s.db.Inbounds[i].ID == id {
			if err := fn(&s.db.Inbounds[i]); err != nil {
				return err
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("入站不存在: %s", id)
}

// validateInbound 校验入站字段（端口唯一性在调用方持锁外另行检查）。
func (s *Store) validateInbound(in *Inbound, excludeID string) error {
	if !protocols[in.Protocol] {
		return fmt.Errorf("不支持的协议: %s", in.Protocol)
	}
	if !transports[in.Transport] {
		return fmt.Errorf("不支持的传输: %s", in.Transport)
	}
	if in.Protocol == "shadowsocks" && !ssMethods[in.SSMethod] {
		return fmt.Errorf("不支持的加密方式: %s", in.SSMethod)
	}
	if in.Protocol == "hysteria2" && in.Transport != "tcp" {
		return fmt.Errorf("hysteria2 仅支持 tcp（UDP 内建），请勿选择其他传输")
	}
	st := s.GetSettings()
	if err := validPort(in.Port, st.PanelPort, st.ClashPort, st.V2RayPort); err != nil {
		return err
	}
	if in.TLSEnabled && in.TLSType == "tls" && (in.CertPath == "" || in.KeyPath == "") {
		return fmt.Errorf("TLS 证书模式需要填写证书与私钥路径")
	}
	if in.TLSEnabled && in.TLSType == "reality" && (in.RealityPriv == "" || in.RealityDest == "") {
		return fmt.Errorf("Reality 需要私钥与握手目标")
	}
	if in.Transport == "ws" && in.WSPath == "" {
		in.WSPath = "/"
	}
	if in.Transport == "grpc" && in.GRPCService == "" {
		return fmt.Errorf("gRPC 传输需要 service name")
	}
	return nil
}

func (s *Store) portInUse(port int, excludeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, in := range s.db.Inbounds {
		if in.ID != excludeID && in.Port == port {
			return true
		}
	}
	return false
}

func (s *Store) AddInbound(in *Inbound) error {
	st := s.GetSettings()
	if err := validPort(in.Port, st.PanelPort, st.ClashPort, st.V2RayPort); err != nil {
		return err
	}
	if s.portInUse(in.Port, "") {
		return fmt.Errorf("端口 %d 已被其他入站占用", in.Port)
	}
	if err := s.validateInbound(in, ""); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in.ID = newID()
	in.Tag = "in-" + in.ID
	if in.Listen == "" {
		in.Listen = "::"
	}
	s.db.Inbounds = append(s.db.Inbounds, *in)
	return s.saveLocked()
}

func (s *Store) UpdateInbound(in *Inbound) error {
	if s.portInUse(in.Port, in.ID) {
		return fmt.Errorf("端口 %d 已被其他入站占用", in.Port)
	}
	if err := s.validateInbound(in, in.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.db.Inbounds {
		if s.db.Inbounds[i].ID == in.ID {
			keep := s.db.Inbounds[i].Clients
			keepUp, keepDown := s.db.Inbounds[i].Up, s.db.Inbounds[i].Down
			keepTag, keepCreated := s.db.Inbounds[i].Tag, s.db.Inbounds[i].CreatedAt
			in.Clients = keep
			in.Up, in.Down = keepUp, keepDown
			in.Tag, in.CreatedAt = keepTag, keepCreated
			s.db.Inbounds[i] = *in
			return s.saveLocked()
		}
	}
	return fmt.Errorf("入站不存在: %s", in.ID)
}

func (s *Store) DeleteInbound(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.db.Inbounds {
		if s.db.Inbounds[i].ID == id {
			s.db.Inbounds = append(s.db.Inbounds[:i], s.db.Inbounds[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("入站不存在: %s", id)
}

// AddClient 给入站加客户端；UUID/口令缺省自动生成。
func (s *Store) AddClient(inboundID string, c *Client) error {
	if c.Name == "" {
		return fmt.Errorf("客户端备注不能为空")
	}
	return s.mutateInbound(inboundID, func(in *Inbound) error {
		for _, ex := range in.Clients {
			if ex.Name == c.Name {
				return fmt.Errorf("该入站下已存在同名客户端: %s", c.Name)
			}
		}
		c.ID = newID()
		c.InboundID = inboundID
		c.Token = newToken()
		c.Enabled = true
		switch in.Protocol {
		case "vless", "vmess":
			if c.UUID == "" {
				c.UUID = newUUID()
			}
		case "trojan", "hysteria2":
			if c.Password == "" {
				c.Password = randomHex(12)
			}
		case "shadowsocks":
			if c.Password == "" {
				if strings.HasPrefix(in.SSMethod, "2022-") {
					// 2022-blake3 系列要求 base64 编码的定长密钥（aes-128 用 16 字节，其余 32 字节），
					// 否则 sing-box 启动时报 missing psk（check 阶段查不出来）
					keyLen := 32
					if in.SSMethod == "2022-blake3-aes-128-gcm" {
						keyLen = 16
					}
					kb := make([]byte, keyLen)
					rand.Read(kb)
					c.Password = base64.StdEncoding.EncodeToString(kb)
				} else {
					c.Password = randomHex(12)
				}
			}
		}
		in.Clients = append(in.Clients, *c)
		return nil
	})
}

func (s *Store) UpdateClient(inboundID, clientID string, upd Client) error {
	return s.mutateInbound(inboundID, func(in *Inbound) error {
		for i := range in.Clients {
			if in.Clients[i].ID == clientID {
				upd.ID = clientID
				upd.InboundID = inboundID
				upd.Token = in.Clients[i].Token
				upd.Up = in.Clients[i].Up
				upd.Down = in.Clients[i].Down
				in.Clients[i] = upd
				return nil
			}
		}
		return fmt.Errorf("客户端不存在: %s", clientID)
	})
}

func (s *Store) DeleteClient(inboundID, clientID string) error {
	return s.mutateInbound(inboundID, func(in *Inbound) error {
		for i := range in.Clients {
			if in.Clients[i].ID == clientID {
				in.Clients = append(in.Clients[:i], in.Clients[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("客户端不存在: %s", clientID)
	})
}

// FindClientByToken 按订阅 token 找客户端及其入站。
func (s *Store) FindClientByToken(token string) (Client, Inbound, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, in := range s.db.Inbounds {
		for _, c := range in.Clients {
			if c.Token == token {
				return c, in, true
			}
		}
	}
	return Client{}, Inbound{}, false
}

// AddTraffic 累加流量计数（collector 调用），并返回是否触发限额。
func (s *Store) AddTraffic(inboundID, clientID string, up, down int64) (inLimited, clLimited bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.db.Inbounds {
		if s.db.Inbounds[i].ID != inboundID {
			continue
		}
		s.db.Inbounds[i].Up += up
		s.db.Inbounds[i].Down += down
		if s.db.Inbounds[i].TotalLimitGB > 0 &&
			float64(s.db.Inbounds[i].Up+s.db.Inbounds[i].Down) >= s.db.Inbounds[i].TotalLimitGB*1e9 {
			inLimited = true
		}
		for j := range s.db.Inbounds[i].Clients {
			if s.db.Inbounds[i].Clients[j].ID == clientID {
				s.db.Inbounds[i].Clients[j].Up += up
				s.db.Inbounds[i].Clients[j].Down += down
				if s.db.Inbounds[i].Clients[j].TotalLimitGB > 0 &&
					float64(s.db.Inbounds[i].Clients[j].Up+s.db.Inbounds[i].Clients[j].Down) >= s.db.Inbounds[i].Clients[j].TotalLimitGB*1e9 {
					clLimited = true
				}
			}
		}
	}
	_ = s.saveLocked()
	return
}

// SetTrafficMax 供 v2ray stats 累计值使用：只接受更大的值（核心重启后计数归零不回退）。
func (s *Store) SetTrafficMax(inboundID, clientID string, up, down int64) (inLimited, clLimited bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.db.Inbounds {
		if s.db.Inbounds[i].ID != inboundID {
			continue
		}
		if up > s.db.Inbounds[i].Up {
			s.db.Inbounds[i].Up = up
		}
		if down > s.db.Inbounds[i].Down {
			s.db.Inbounds[i].Down = down
		}
		if s.db.Inbounds[i].TotalLimitGB > 0 &&
			float64(s.db.Inbounds[i].Up+s.db.Inbounds[i].Down) >= s.db.Inbounds[i].TotalLimitGB*1e9 {
			inLimited = true
		}
		for j := range s.db.Inbounds[i].Clients {
			if s.db.Inbounds[i].Clients[j].ID == clientID {
				if up > s.db.Inbounds[i].Clients[j].Up {
					s.db.Inbounds[i].Clients[j].Up = up
				}
				if down > s.db.Inbounds[i].Clients[j].Down {
					s.db.Inbounds[i].Clients[j].Down = down
				}
				if s.db.Inbounds[i].Clients[j].TotalLimitGB > 0 &&
					float64(s.db.Inbounds[i].Clients[j].Up+s.db.Inbounds[i].Clients[j].Down) >= s.db.Inbounds[i].Clients[j].TotalLimitGB*1e9 {
					clLimited = true
				}
			}
		}
	}
	_ = s.saveLocked()
	return
}
