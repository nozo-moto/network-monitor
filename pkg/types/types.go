package types

import "time"

type NetworkStats struct {
	Interface   string
	BytesRecv   uint64
	BytesSent   uint64
	PacketsRecv uint64
	PacketsSent uint64
	Errin       uint64
	Errout      uint64
	Dropin      uint64
	Dropout     uint64
	Timestamp   time.Time
}

type SystemStats struct {
	CPUPercent  float64
	MemoryUsed  uint64
	MemoryTotal uint64
	MemoryPerc  float64
	Connections int
	Goroutines  int
	Timestamp   time.Time
}

type ConnectionInfo struct {
	LocalAddr  string
	RemoteAddr string
	State      string
	Type       string
}

type Metrics struct {
	Network *NetworkStats
	System  *SystemStats
	Conns   []ConnectionInfo
}