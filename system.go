package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SystemInfo struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemTotal    uint64  `json:"mem_total"`
	MemUsed     uint64  `json:"mem_used"`
	MemPercent  float64 `json:"mem_percent"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskPercent float64 `json:"disk_percent"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	Uptime      int64   `json:"uptime"`
}

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		for i, s := range fields {
			v, _ := strconv.ParseUint(s, 10, 64)
			total += v
			if i == 3 || i == 4 { // idle + iowait
				idle += v
			}
		}
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("未找到 cpu 行")
}

func GetSystemInfo() SystemInfo {
	var info SystemInfo
	idle1, total1, err1 := readCPUStat()
	time.Sleep(150 * time.Millisecond)
	idle2, total2, err2 := readCPUStat()
	if err1 == nil && err2 == nil && total2 > total1 {
		info.CPUPercent = float64((total2-total1)-(idle2-idle1)) / float64(total2-total1) * 100
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				avail = v * 1024
			}
		}
		info.MemTotal = total
		if total > 0 {
			info.MemUsed = total - avail
			info.MemPercent = float64(info.MemUsed) / float64(total) * 100
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err == nil {
		total := fs.Blocks * uint64(fs.Bsize)
		free := fs.Bfree * uint64(fs.Bsize)
		info.DiskTotal = total
		info.DiskUsed = total - free
		if total > 0 {
			info.DiskPercent = float64(info.DiskUsed) / float64(total) * 100
		}
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(data))
		if len(f) >= 3 {
			info.Load1, _ = strconv.ParseFloat(f[0], 64)
			info.Load5, _ = strconv.ParseFloat(f[1], 64)
			info.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(data))
		if len(f) >= 1 {
			u, _ := strconv.ParseFloat(f[0], 64)
			info.Uptime = int64(u)
		}
	}
	return info
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
