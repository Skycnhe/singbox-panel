package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// hostForLinks：订阅域名优先，否则用请求 Host（去掉端口）。
func hostForLinks(st Settings, reqHost string) string {
	if st.SubDomain != "" {
		return st.SubDomain
	}
	if h := reqHost; h != "" {
		if idx := strings.LastIndex(h, ":"); idx > 0 && !strings.Contains(h[idx+1:], "]") {
			return h[:idx]
		}
		return h
	}
	return "127.0.0.1"
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// buildClientLink 生成各协议客户端链接。host 为订阅域名或请求 Host。
func buildClientLink(in Inbound, c Client, host string) (string, error) {
	remark := firstNonEmpty(c.Name, in.Remark)
	q := url.Values{}
	switch in.Protocol {
	case "vless":
		q.Set("encryption", "none")
		if c.Flow != "" && in.Transport == "tcp" && in.TLSEnabled {
			q.Set("flow", c.Flow)
		}
		setTransportParams(q, in)
		setSecurityParams(q, in)
		u := &url.URL{
			Scheme:   "vless",
			User:     url.User(c.UUID),
			Host:     fmt.Sprintf("%s:%d", host, in.Port),
			RawQuery: q.Encode(),
			Fragment: remark,
		}
		return u.String(), nil
	case "vmess":
		vm := map[string]any{
			"v": "2", "ps": remark, "add": host, "port": strconv.Itoa(in.Port),
			"id": c.UUID, "aid": "0", "scy": "auto", "net": in.Transport, "type": "none",
		}
		switch in.Transport {
		case "ws":
			vm["path"] = in.WSPath
			vm["host"] = in.WSHost
		case "grpc":
			vm["path"] = in.GRPCService
		case "httpupgrade":
			vm["path"] = in.HUPath
			vm["host"] = in.HUHost
		}
		setVMessSecurity(vm, in)
		data, _ := json.Marshal(vm)
		return "vmess://" + base64.StdEncoding.EncodeToString(data), nil
	case "trojan":
		setSecurityParams(q, in)
		u := &url.URL{
			Scheme:   "trojan",
			User:     url.User(c.Password),
			Host:     fmt.Sprintf("%s:%d", host, in.Port),
			RawQuery: q.Encode(),
			Fragment: remark,
		}
		return u.String(), nil
	case "shadowsocks":
		pw := c.Password
		if pw == "" {
			pw = in.SSPassword
		}
		raw := fmt.Sprintf("%s:%s@%s:%d", in.SSMethod, pw, host, in.Port)
		return "ss://" + b64url(raw) + "#" + url.PathEscape(remark), nil
	case "hysteria2":
		if in.ServerName != "" {
			q.Set("sni", in.ServerName)
		}
		if in.TLSType == "self" {
			q.Set("insecure", "1")
		}
		u := &url.URL{
			Scheme:   "hysteria2",
			User:     url.User(c.Password),
			Host:     fmt.Sprintf("%s:%d", host, in.Port),
			RawQuery: q.Encode(),
			Fragment: remark,
		}
		return u.String(), nil
	}
	return "", fmt.Errorf("不支持的协议: %s", in.Protocol)
}

func setTransportParams(q url.Values, in Inbound) {
	switch in.Transport {
	case "ws":
		q.Set("type", "ws")
		q.Set("path", in.WSPath)
		if in.WSHost != "" {
			q.Set("host", in.WSHost)
		}
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", in.GRPCService)
	case "httpupgrade":
		q.Set("type", "httpupgrade")
		q.Set("path", in.HUPath)
		if in.HUHost != "" {
			q.Set("host", in.HUHost)
		}
	default:
		q.Set("type", "tcp")
	}
}

func setSecurityParams(q url.Values, in Inbound) {
	if !in.TLSEnabled {
		q.Set("security", "none")
		return
	}
	switch in.TLSType {
	case "reality":
		q.Set("security", "reality")
		if in.ServerName != "" {
			q.Set("sni", in.ServerName)
		}
		q.Set("fp", "chrome")
		q.Set("pbk", in.RealityPub)
		q.Set("sid", in.RealitySID)
	case "tls", "self":
		q.Set("security", "tls")
		if in.ServerName != "" {
			q.Set("sni", in.ServerName)
		}
		if in.TLSType == "self" {
			q.Set("allowInsecure", "1")
		}
	}
}

func setVMessSecurity(vm map[string]any, in Inbound) {
	if !in.TLSEnabled {
		vm["tls"] = ""
		return
	}
	switch in.TLSType {
	case "reality":
		vm["tls"] = "reality"
		vm["sni"] = in.ServerName
		vm["pbk"] = in.RealityPub
		vm["sid"] = in.RealitySID
		vm["fp"] = "chrome"
	case "tls", "self":
		vm["tls"] = "tls"
		vm["sni"] = in.ServerName
		if in.TLSType == "self" {
			vm["allowInsecure"] = true
		}
	}
}

// buildSubConfig 生成某用户的 sing-box JSON 订阅配置。
func buildSubConfig(in Inbound, c Client, host string) (map[string]any, error) {
	outbound, err := clientOutbound(in, c, host)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "info"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "dns-remote", "type": "tls", "server": "8.8.8.8", "server_port": 853, "detour": "proxy"},
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"rules": []any{},
			"final": "proxy",
		},
	}
	return cfg, nil
}

func clientOutbound(in Inbound, c Client, host string) (map[string]any, error) {
	ob := map[string]any{
		"type":        in.Protocol,
		"tag":         "proxy",
		"server":      host,
		"server_port": in.Port,
	}
	switch in.Protocol {
	case "vless":
		ob["uuid"] = c.UUID
		if c.Flow != "" && in.Transport == "tcp" && in.TLSEnabled {
			ob["flow"] = c.Flow
		}
	case "vmess":
		ob["uuid"] = c.UUID
		ob["alter_id"] = 0
		ob["security"] = "auto"
	case "trojan":
		ob["password"] = c.Password
	case "shadowsocks":
		ob["method"] = in.SSMethod
		pw := c.Password
		if pw == "" {
			pw = in.SSPassword
		}
		ob["password"] = pw
	case "hysteria2":
		ob["password"] = c.Password
	}
	if t, err := transportObj(in); err != nil {
		return nil, err
	} else if t != nil {
		ob["transport"] = t
	}
	if in.Protocol == "hysteria2" {
		ob["tls"] = map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(in.ServerName, host),
			"insecure":    in.TLSType == "self",
		}
		return ob, nil
	}
	if in.TLSEnabled {
		var t map[string]any
		if in.TLSType == "reality" {
			// 客户端 Reality：用公钥 + short_id，不含服务端的私钥与握手目标
			t = map[string]any{
				"enabled":     true,
				"server_name": in.ServerName,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": in.RealityPub,
					"short_id":   in.RealitySID,
				},
			}
		} else {
			t = map[string]any{
				"enabled":     true,
				"server_name": in.ServerName,
				"insecure":    in.TLSType == "self",
			}
		}
		ob["tls"] = t
	}
	return ob, nil
}
