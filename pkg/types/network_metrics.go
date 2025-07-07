package types

// NetworkMetrics contains all network-related metrics for processes
type NetworkMetrics struct {
	Connections     []ConnectionInfo
	ProcessNetworks []ProcessNetwork
}

// ProcessNetwork contains network statistics for a single process
type ProcessNetwork struct {
	PID             int
	Name            string
	BytesSent       uint64
	BytesRecv       uint64
	ConnectionCount int
}