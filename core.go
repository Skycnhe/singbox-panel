package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ---------- Reality 密钥对 / 自签证书 ----------

func genRealityKeypair() (priv, pub string, err error) {
	var privBytes [32]byte
	if _, err := rand.Read(privBytes[:]); err != nil {
		return "", "", err
	}
	pubBytes, err := curve25519.X25519(privBytes[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(privBytes[:]), enc.EncodeToString(pubBytes), nil
}

func genSelfSignedCert(dir, name, cn string) (certPath, keyPath string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	if ip := net.ParseIP(cn); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = certOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = keyOut.Close()
	return certPath, keyPath, nil
}

// ---------- 核心进程管理 ----------

type CoreManager struct {
	mu      sync.Mutex
	binPath string
	cfgPath string
	cmd     *exec.Cmd
	running bool
	started time.Time
	logMu   sync.Mutex
	logs    []string
	version string
}

func NewCoreManager(dataDir, binPath string) *CoreManager {
	return &CoreManager{
		binPath: binPath,
		cfgPath: filepath.Join(dataDir, "singbox", "config.json"),
	}
}

func (c *CoreManager) SetBinPath(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binPath = p
	c.version = ""
}

func (c *CoreManager) appendLog(line string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	c.logs = append(c.logs, line)
	if len(c.logs) > 3000 {
		c.logs = c.logs[len(c.logs)-3000:]
	}
}

func (c *CoreManager) Logs(lines int) []string {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if lines <= 0 || lines > len(c.logs) {
		lines = len(c.logs)
	}
	out := make([]string, lines)
	copy(out, c.logs[len(c.logs)-lines:])
	return out
}

func (c *CoreManager) Status() (running bool, pid int, uptime time.Duration, version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running && c.cmd != nil && c.cmd.Process != nil {
		return true, c.cmd.Process.Pid, time.Since(c.started), c.version
	}
	return false, 0, 0, c.version
}

func (c *CoreManager) WriteConfig(cfg map[string]any) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.cfgPath, data, 0o600)
}

func (c *CoreManager) ConfigPath() string { return c.cfgPath }

// Check 运行 sing-box check -c，返回完整输出与错误。
func (c *CoreManager) Check() (string, error) {
	cmd := exec.Command(c.binPath, "check", "-c", c.cfgPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func (c *CoreManager) Version() string {
	c.mu.Lock()
	ver := c.version
	bin := c.binPath
	c.mu.Unlock()
	if ver != "" {
		return ver
	}
	cmd := exec.Command(bin, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	line := strings.TrimSpace(out.String())
	if idx := strings.Index(line, "\n"); idx > 0 {
		line = line[:idx]
	}
	c.mu.Lock()
	c.version = line
	c.mu.Unlock()
	return line
}

func (c *CoreManager) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("sing-box 已在运行")
	}
	if _, err := os.Stat(c.cfgPath); err != nil {
		return fmt.Errorf("配置文件不存在，请先应用配置: %w", err)
	}
	cmd := exec.Command(c.binPath, "run", "-c", c.cfgPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}
	c.cmd = cmd
	c.running = true
	c.started = time.Now()
	c.appendLog(fmt.Sprintf("[panel] sing-box 已启动 pid=%d", cmd.Process.Pid))
	go c.pumpLogs(stdout)
	go c.pumpLogs(stderr)
	go func() {
		_ = cmd.Wait()
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		c.appendLog("[panel] sing-box 进程已退出")
	}()
	return nil
}

func (c *CoreManager) pumpLogs(r io.Reader) {
	buf := make([]byte, 4096)
	rest := ""
	for {
		n, err := r.Read(buf)
		if n > 0 {
			rest += string(buf[:n])
			for {
				idx := strings.IndexByte(rest, '\n')
				if idx < 0 {
					break
				}
				c.appendLog(strings.TrimRight(rest[:idx], "\r"))
				rest = rest[idx+1:]
			}
		}
		if err != nil {
			if rest != "" {
				c.appendLog(rest)
			}
			return
		}
	}
}

func (c *CoreManager) Stop() error {
	c.mu.Lock()
	cmd := c.cmd
	running := c.running
	c.mu.Unlock()
	if !running || cmd == nil || cmd.Process == nil {
		return fmt.Errorf("sing-box 未运行")
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()
	c.appendLog("[panel] sing-box 已停止")
	return nil
}

func (c *CoreManager) Restart() error {
	_ = c.Stop()
	time.Sleep(300 * time.Millisecond)
	return c.Start()
}

// ---------- 二进制解析与下载 ----------

func resolveBinPath(st Settings, dataDir string) string {
	if st.SingboxPath != "" {
		if !filepath.IsAbs(st.SingboxPath) {
			if abs, err := filepath.Abs(st.SingboxPath); err == nil {
				return abs
			}
		}
		return st.SingboxPath
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	local := filepath.Join(dataDir, "bin", "sing-box")
	if _, err := os.Stat(local); err == nil {
		if abs, err := filepath.Abs(local); err == nil {
			return abs
		}
		return local
	}
	return "sing-box"
}

// DownloadSingbox 从 GitHub releases 下载指定版本（空则取 latest），解压安装到数据目录。
func DownloadSingbox(dataDir, version string) (string, error) {
	if version == "" {
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
		req.Header.Set("User-Agent", "singbox-panel")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("获取最新版本失败: %w", err)
		}
		defer resp.Body.Close()
		var rel struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
			return "", fmt.Errorf("解析最新版本失败: %w", err)
		}
		version = strings.TrimPrefix(rel.TagName, "v")
	}
	version = strings.TrimPrefix(version, "v")
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("不支持的架构: %s（仅 amd64/arm64）", arch)
	}
	asset := fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", version, arch)
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", version, asset)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "singbox-panel")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("下载失败: HTTP %d（版本 %s 可能不存在）", resp.StatusCode, version)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	binDir := filepath.Join(dataDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	target := filepath.Join(binDir, "sing-box")
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == "sing-box" {
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return "", err
			}
			f.Close()
			_ = os.Chmod(target, 0o755)
			if abs, err := filepath.Abs(target); err == nil {
				return abs, nil
			}
			return target, nil
		}
	}
	return "", fmt.Errorf("压缩包中未找到 sing-box 二进制")
}
