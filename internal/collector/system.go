package collector

import (
	"fmt"
	"runtime"
	"time"

	"github.com/nozo-moto/network-monitor/pkg/types"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

type SystemCollector struct{}

func NewSystemCollector() *SystemCollector {
	return &SystemCollector{}
}

func (sc *SystemCollector) Collect() (*types.SystemStats, error) {
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	conns, err := psnet.Connections("all")
	if err != nil {
		conns = []psnet.ConnectionStat{}
	}

	stats := &types.SystemStats{
		CPUPercent:  cpuPercent[0],
		MemoryUsed:  memInfo.Used,
		MemoryTotal: memInfo.Total,
		MemoryPerc:  memInfo.UsedPercent,
		Connections: len(conns),
		Goroutines:  runtime.NumGoroutine(),
		Timestamp:   time.Now(),
	}

	return stats, nil
}