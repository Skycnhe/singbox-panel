package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// ---------- 极简 protobuf 读写（仅用于 v2ray stats QueryStats） ----------

func pbVarint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func pbString(field int, s string) []byte {
	out := pbVarint(uint64(field<<3 | 2))
	out = append(out, pbVarint(uint64(len(s)))...)
	return append(out, s...)
}

type pbReader struct {
	b []byte
}

func (r *pbReader) varint() (uint64, bool) {
	var v uint64
	var shift uint
	for i := 0; i < 10; i++ {
		if len(r.b) == 0 {
			return 0, false
		}
		b := r.b[0]
		r.b = r.b[1:]
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, true
		}
		shift += 7
	}
	return 0, false
}

// next 返回下一个字段 (fieldNum, wireType, payload)。
func (r *pbReader) next() (int, int, []byte, bool) {
	tag, ok := r.varint()
	if !ok {
		return 0, 0, nil, false
	}
	field, wire := int(tag>>3), int(tag&7)
	switch wire {
	case 0:
		v, ok := r.varint()
		if !ok {
			return 0, 0, nil, false
		}
		return field, wire, pbVarint(v), true
	case 2:
		n, ok := r.varint()
		if !ok {
			return 0, 0, nil, false
		}
		if int(n) > len(r.b) {
			return 0, 0, nil, false
		}
		p := r.b[:n]
		r.b = r.b[n:]
		return field, wire, p, true
	case 5:
		if len(r.b) < 4 {
			return 0, 0, nil, false
		}
		p := r.b[:4]
		r.b = r.b[4:]
		return field, wire, p, true
	case 1:
		if len(r.b) < 8 {
			return 0, 0, nil, false
		}
		p := r.b[:8]
		r.b = r.b[8:]
		return field, wire, p, true
	}
	return 0, 0, nil, false
}

// ---------- v2ray stats gRPC 客户端 ----------

// queryV2RayStats 向 sing-box 的 v2ray_api 查询 QueryStats，返回 name->value。
// 服务名：v2ray.core.app.stats.command.StatsService，方法 QueryStats。
func queryV2RayStats(addr, pattern string) (map[string]int64, error) {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	// QueryStatsRequest: field 1 pattern(string), field 2 reset(bool, 默认 false 可省略)
	msg := pbString(1, pattern)
	frame := make([]byte, 5)
	frame[0] = 0 // 未压缩
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	frame = append(frame, msg...)
	url := "http://" + addr + "/v2ray.core.app.stats.command.StatsService/QueryStats"
	req, err := http.NewRequest("POST", url, strings.NewReader(string(frame)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("v2ray api HTTP %d", resp.StatusCode)
	}
	// 解析 gRPC 数据帧，取 QueryStatsResponse 的 stat 列表
	out := map[string]int64{}
	rest := body
	for len(rest) >= 5 {
		flag := rest[0]
		n := int(binary.BigEndian.Uint32(rest[1:5]))
		if len(rest) < 5+n {
			break
		}
		payload := rest[5 : 5+n]
		rest = rest[5+n:]
		if flag != 0 {
			continue
		}
		r := &pbReader{b: payload}
		for {
			field, wire, p, ok := r.next()
			if !ok {
				break
			}
			if field == 1 && wire == 2 {
				// Stat 消息：field 1 name(string), field 2 value(int64)
				sr := &pbReader{b: p}
				var name string
				var value int64
				for {
					f2, w2, p2, ok2 := sr.next()
					if !ok2 {
						break
					}
					if f2 == 1 && w2 == 2 {
						name = string(p2)
					}
					if f2 == 2 && w2 == 0 {
						vr := &pbReader{b: p2}
						v, _ := vr.varint()
						value = int64(v)
					}
				}
				if name != "" {
					out[name] = value
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("v2ray api 未返回任何统计（请确认 sing-box 已启用 v2ray_api 且入站在 stats 列表中）")
	}
	return out, nil
}

// ---------- 流量收集器 ----------

type StatsCollector struct {
	app       *App
	mu        sync.Mutex
	source    string // 当前实际口径：v2ray | clash | none
	v2rayFail int
	prevConn  map[string]connSnap
}

type connSnap struct {
	up, down  int64
	inboundID string
	clientID  string
}

type clashConn struct {
	ID       string `json:"id"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Metadata struct {
		Inbound string `json:"inbound"`
		User    string `json:"user"`
	} `json:"metadata"`
}

func NewStatsCollector(app *App) *StatsCollector {
	return &StatsCollector{app: app, source: "none", prevConn: map[string]connSnap{}}
}

func (sc *StatsCollector) Source() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.source
}

func (sc *StatsCollector) setSource(s string) {
	sc.mu.Lock()
	sc.source = s
	sc.mu.Unlock()
}

// Run 每 5 秒采集一次；v2ray 成功则用累计值，否则退化为 clash 连接快照聚合。
func (sc *StatsCollector) Run(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			sc.collect()
		}
	}
}

func (sc *StatsCollector) collect() {
	st := sc.app.store.GetSettings()
	if sc.app.coreRunning() && st.StatsSource != "clash" {
		if sc.collectV2Ray(st) {
			sc.setSource("v2ray")
			sc.v2rayFail = 0
			return
		}
		sc.v2rayFail++
	}
	if sc.app.coreRunning() && st.StatsSource != "v2ray" {
		if sc.collectClash(st) {
			sc.setSource("clash")
			return
		}
	}
	// 核心未运行或两种口径都失败：保持上次口径，界面据此提示
}

// collectV2Ray：用累计值写库（只增不减，核心重启计数归零时不回退）。
func (sc *StatsCollector) collectV2Ray(st Settings) bool {
	stats, err := queryV2RayStats(fmt.Sprintf("127.0.0.1:%d", st.V2RayPort), "")
	if err != nil {
		return false
	}
	// name 形如 user>>><name|uuid>>>traffic>>>uplink / inbound>>><tag>>>traffic>>>uplink
	inbounds := sc.app.store.ListInbounds()
	byTag := map[string]Inbound{}
	byName := map[string]Client{}
	byUUID := map[string]Client{}
	for _, in := range inbounds {
		byTag[in.Tag] = in
		for _, c := range in.Clients {
			byName[c.Name] = c
			if c.UUID != "" {
				byUUID[c.UUID] = c
			}
		}
	}
	// 先聚合到 client/inbound 粒度
	type agg struct{ up, down int64 }
	clientAgg := map[string]*agg{}
	inboundAgg := map[string]*agg{}
	for name, v := range stats {
		// 形如 user>>><name|uuid>>>traffic>>>uplink
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		kind, id, dir := parts[0], parts[1], parts[3]
		if dir != "uplink" && dir != "downlink" {
			continue
		}
		switch kind {
		case "user":
			c, ok := byName[id]
			if !ok {
				c, ok = byUUID[id]
			}
			if !ok {
				continue
			}
			a := clientAgg[c.ID]
			if a == nil {
				a = &agg{}
				clientAgg[c.ID] = a
			}
			if dir == "uplink" {
				a.up = v
			} else {
				a.down = v
			}
		case "inbound":
			a := inboundAgg[id]
			if a == nil {
				a = &agg{}
				inboundAgg[id] = a
			}
			if dir == "uplink" {
				a.up = v
			} else {
				a.down = v
			}
		}
	}
	// 入站累计：优先用 inbound 粒度；缺失时用其客户端之和
	for _, in := range inbounds {
		ia := inboundAgg[in.Tag]
		if ia != nil {
			inLimited, _ := sc.app.store.SetTrafficMax(in.ID, "", ia.up, ia.down)
			if inLimited {
				sc.app.enforceLimit(in.ID, "")
			}
		}
		for _, c := range in.Clients {
			if ca, ok := clientAgg[c.ID]; ok {
				_, clLimited := sc.app.store.SetTrafficMax(in.ID, c.ID, ca.up, ca.down)
				if clLimited {
					sc.app.enforceLimit(in.ID, c.ID)
				}
			}
		}
	}
	return true
}

// collectClash：对 /connections 快照做差分，归因到入站/用户。
func (sc *StatsCollector) collectClash(st Settings) bool {
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/connections", st.ClashPort), nil)
	req.Header.Set("Authorization", "Bearer "+st.ClashSecret)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		Connections []clashConn `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}
	inbounds := sc.app.store.ListInbounds()
	byTag := map[string]Inbound{}
	byName := map[string]Client{}
	byUUID := map[string]Client{}
	for _, in := range inbounds {
		byTag[in.Tag] = in
		for _, c := range in.Clients {
			byName[c.Name] = c
			if c.UUID != "" {
				byUUID[c.UUID] = c
			}
		}
	}
	cur := map[string]connSnap{}
	for _, cc := range body.Connections {
		var inboundID, clientID string
		if in, ok := byTag[cc.Metadata.Inbound]; ok {
			inboundID = in.ID
		}
		if cc.Metadata.User != "" {
			if c, ok := byName[cc.Metadata.User]; ok {
				clientID = c.ID
				inboundID = c.InboundID
			} else if c, ok := byUUID[cc.Metadata.User]; ok {
				clientID = c.ID
				inboundID = c.InboundID
			}
		}
		snap := connSnap{up: cc.Upload, down: cc.Download, inboundID: inboundID, clientID: clientID}
		cur[cc.ID] = snap
		if prev, ok := sc.prevConn[cc.ID]; ok {
			du, dd := cc.Upload-prev.up, cc.Download-prev.down
			if du < 0 {
				du = cc.Upload
			}
			if dd < 0 {
				dd = cc.Download
			}
			if (du > 0 || dd > 0) && inboundID != "" {
				inLimited, clLimited := sc.app.store.AddTraffic(inboundID, clientID, du, dd)
				if inLimited {
					sc.app.enforceLimit(inboundID, "")
				}
				if clLimited {
					sc.app.enforceLimit(inboundID, clientID)
				}
			}
		}
	}
	sc.prevConn = cur
	return true
}
