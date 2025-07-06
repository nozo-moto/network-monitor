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

type NetworkFlowStats struct {
	SourceIP      string
	DestIP        string
	BytesSent     uint64
	BytesReceived uint64
	PacketCount   uint64
	FirstSeen     time.Time
	LastSeen      time.Time
}

type ConnectionHistory struct {
	LocalAddr  string
	RemoteAddr string
	State      string
	StartTime  time.Time
	EndTime    *time.Time
	Duration   time.Duration
	BytesSent  uint64
	BytesRecv  uint64
}

type TrafficDataPoint struct {
	Time      time.Time
	BytesIn   uint64
	BytesOut  uint64
	Connections int
}

type ProcessNetworkStats struct {
	PID         int32
	Name        string
	BytesSent   uint64
	BytesRecv   uint64
	Connections int
}

type LatencyStats struct {
	Host        string
	IP          string
	MinRTT      time.Duration
	AvgRTT      time.Duration
	MaxRTT      time.Duration
	PacketLoss  float64
	LastChecked time.Time
}

type Metrics struct {
	Network        *NetworkStats
	System         *SystemStats
	Conns          []ConnectionInfo
	FlowStats      map[string]*NetworkFlowStats // key: src->dst
	ConnHistory    []ConnectionHistory
	CurrentTime    time.Time
	TrafficHistory []TrafficDataPoint // Time series data for line graph
	ProcessStats   []ProcessNetworkStats
	LatencyStats   []LatencyStats
}