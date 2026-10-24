package main

import (
	"fmt"
	"net"
	"strconv"
)

// buildConfig 根据入站/用户生成 sing-box config。
// 只包含启用的入站与启用的客户端；禁用的不写入配置（即等效停用）。
func buildConfig(st Settings, inbounds []Inbound) (map[string]any, error) {
	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				// sing-box 1.12+ 新 DNS 格式：type/server/server_port（旧 address URL 格式在 1.14 已移除）
				// 注意：detour 指向 direct 会被 1.14 拒绝（"detour to an empty direct outbound"），直接走默认直连即可
				map[string]any{"tag": "dns-remote", "type": "tls", "server": "8.8.8.8", "server_port": 853},
			},
		},
		"inbounds": []any{},
		// sing-box 1.13+ 已移除 dns 出站类型：DNS 由内置解析处理，不再需要 dns-out 与 dns 规则
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"rules": []any{},
			"final": "direct",
		},
	}

	var sbInbounds []any
	var v2rayTags []string
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}
		ib, err := inboundToSingbox(in)
		if err != nil {
			return nil, err
		}
		sbInbounds = append(sbInbounds, ib)
		v2rayTags = append(v2rayTags, in.Tag)
	}
	cfg["inbounds"] = sbInbounds

	exp := map[string]any{
		"clash_api": map[string]any{
			"external_controller": fmt.Sprintf("127.0.0.1:%d", st.ClashPort),
			"secret":              st.ClashSecret,
		},
	}
	if st.EnableV2RayAPI {
		exp["v2ray_api"] = map[string]any{
			"listen": fmt.Sprintf("127.0.0.1:%d", st.V2RayPort),
			"stats": map[string]any{
				"enabled":  true,
				"inbounds": v2rayTags,
			},
		}
	}
	cfg["experimental"] = exp
	return cfg, nil
}

func transportObj(in Inbound) (map[string]any, error) {
	switch in.Transport {
	case "tcp":
		return nil, nil
	case "ws":
		t := map[string]any{"type": "ws", "path": in.WSPath}
		if in.WSHost != "" {
			t["headers"] = map[string]any{"Host": in.WSHost}
		}
		return t, nil
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": in.GRPCService}, nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade", "path": in.HUPath}
		if in.HUHost != "" {
			t["host"] = in.HUHost
		}
		return t, nil
	}
	return nil, fmt.Errorf("未知传输: %s", in.Transport)
}

func tlsObj(in Inbound) (map[string]any, error) {
	if !in.TLSEnabled {
		return nil, nil
	}
	t := map[string]any{"enabled": true}
	if in.ServerName != "" {
		t["server_name"] = in.ServerName
	}
	switch in.TLSType {
	case "tls", "self":
		t["certificate_path"] = in.CertPath
		t["key_path"] = in.KeyPath
	case "reality":
		host, port, err := net.SplitHostPort(in.RealityDest)
		if err != nil {
			return nil, fmt.Errorf("Reality 握手目标格式应为 host:port: %w", err)
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("Reality 握手目标端口无效: %s", port)
		}
		t["reality"] = map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      host,
				"server_port": p,
			},
			"private_key": in.RealityPriv,
			"short_id":    in.RealitySID,
		}
	default:
		return nil, fmt.Errorf("未知 TLS 类型: %s", in.TLSType)
	}
	return t, nil
}

func enabledClients(in Inbound) []Client {
	var out []Client
	for _, c := range in.Clients {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func inboundToSingbox(in Inbound) (map[string]any, error) {
	ib := map[string]any{
		"type":        in.Protocol,
		"tag":         in.Tag,
		"listen":      in.Listen,
		"listen_port": in.Port,
	}
	clients := enabledClients(in)
	switch in.Protocol {
	case "vless":
		var users []any
		for _, c := range clients {
			u := map[string]any{"name": c.Name, "uuid": c.UUID}
			// vision 仅在 tcp 原始传输 + TLS 时有效，其他传输下 sing-box 会拒绝
			if c.Flow != "" && in.Transport == "tcp" && in.TLSEnabled {
				u["flow"] = c.Flow
			}
			users = append(users, u)
		}
		ib["users"] = users
	case "vmess":
		var users []any
		for _, c := range clients {
			users = append(users, map[string]any{"name": c.Name, "uuid": c.UUID, "alterId": 0})
		}
		ib["users"] = users
	case "trojan":
		var users []any
		for _, c := range clients {
			users = append(users, map[string]any{"name": c.Name, "password": c.Password})
		}
		ib["users"] = users
	case "shadowsocks":
		ib["method"] = in.SSMethod
		// 不填 network：sing-box 默认同时监听 TCP/UDP（填 "tcp,udp" 会被 check 拒绝）
		// 实测 sing-box 1.14 的 shadowsocks 入站不接受 users 数组（报 missing psk），
		// 2022 与传统加密一律用入站级单口令：取首个启用客户端的口令
		if len(clients) > 0 {
			ib["password"] = clients[0].Password
		} else {
			ib["password"] = in.SSPassword
		}
	case "hysteria2":
		var users []any
		for _, c := range clients {
			users = append(users, map[string]any{"name": c.Name, "password": c.Password})
		}
		ib["users"] = users
		// hysteria2 的 TLS 固定走证书路径，不再走通用 tlsObj
		ib["tls"] = map[string]any{
			"enabled":          true,
			"server_name":      firstNonEmpty(in.ServerName, "localhost"),
			"certificate_path": in.CertPath,
			"key_path":         in.KeyPath,
		}
		return ib, nil
	}
	if t, err := transportObj(in); err != nil {
		return nil, err
	} else if t != nil {
		ib["transport"] = t
	}
	if in.TLSEnabled {
		t, err := tlsObj(in)
		if err != nil {
			return nil, err
		}
		ib["tls"] = t
	}
	return ib, nil
}
