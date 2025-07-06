package collector

import (
	"fmt"
	"time"

	"github.com/nozo-moto/network-monitor/pkg/types"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type ProcessCollector struct {
	lastStats map[int32]*processNetStats
}

type processNetStats struct {
	bytesSent uint64
	bytesRecv uint64
}

func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{
		lastStats: make(map[int32]*processNetStats),
	}
}

func (pc *ProcessCollector) Collect() ([]types.ProcessNetworkStats, error) {
	// Get all connections with process info
	connections, err := net.ConnectionsPid("tcp", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	// Map to track process network usage
	processMap := make(map[int32]*types.ProcessNetworkStats)
	
	// Count connections per process
	for _, conn := range connections {
		if conn.Pid == 0 || conn.Status != "ESTABLISHED" {
			continue
		}
		
		if _, exists := processMap[conn.Pid]; !exists {
			proc, err := process.NewProcess(conn.Pid)
			if err != nil {
				continue
			}
			
			name, _ := proc.Name()
			if name == "" {
				name = fmt.Sprintf("PID %d", conn.Pid)
			}
			
			processMap[conn.Pid] = &types.ProcessNetworkStats{
				PID:         conn.Pid,
				Name:        name,
				Connections: 0,
			}
		}
		
		processMap[conn.Pid].Connections++
	}
	
	// Get network I/O stats for each process (simulated for now)
	// Note: Real per-process network I/O requires platform-specific implementation
	// or eBPF on Linux. For now, we'll estimate based on connections
	currentStats := make(map[int32]*processNetStats)
	
	for pid, procStats := range processMap {
		// Simulate network traffic based on number of connections
		// In a real implementation, this would use platform-specific APIs
		estimatedTraffic := uint64(procStats.Connections) * 1024 * uint64(time.Now().Unix()%100+1)
		
		procStats.BytesSent = estimatedTraffic / 2
		procStats.BytesRecv = estimatedTraffic
		
		// Calculate delta from last measurement
		if last, exists := pc.lastStats[pid]; exists {
			if procStats.BytesSent > last.bytesSent {
				procStats.BytesSent = procStats.BytesSent - last.bytesSent
			}
			if procStats.BytesRecv > last.bytesRecv {
				procStats.BytesRecv = procStats.BytesRecv - last.bytesRecv
			}
		}
		
		currentStats[pid] = &processNetStats{
			bytesSent: procStats.BytesSent,
			bytesRecv: procStats.BytesRecv,
		}
	}
	
	pc.lastStats = currentStats
	
	// Convert map to slice
	var result []types.ProcessNetworkStats
	for _, stats := range processMap {
		result = append(result, *stats)
	}
	
	// Sort by total traffic (sent + received)
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if (result[j].BytesSent + result[j].BytesRecv) > (result[i].BytesSent + result[i].BytesRecv) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	
	return result, nil
}