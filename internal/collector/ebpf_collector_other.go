//go:build !linux
// +build !linux

package collector

import (
	"fmt"
	"github.com/nozo-moto/network-monitor/pkg/types"
)

// NetworkEvent represents a network event captured by eBPF (stub for non-Linux)
type NetworkEvent struct {
	Timestamp uint64
	PID       uint32
	Comm      [16]byte
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	Size      uint32
	Direction uint8 // 0: ingress, 1: egress
}

// EBPFCollector is a stub implementation for non-Linux platforms
type EBPFCollector struct {
	enabled bool
	metrics map[int]types.ProcessNetwork
	events  chan NetworkEvent
}

// NewEBPFCollector creates a new eBPF collector (stub for non-Linux)
func NewEBPFCollector() (*EBPFCollector, error) {
	return &EBPFCollector{
		enabled: false,
		metrics: make(map[int]types.ProcessNetwork),
		events:  make(chan NetworkEvent, 100),
	}, nil
}

// Start initializes and starts the eBPF collector (stub for non-Linux)
func (c *EBPFCollector) Start() error {
	if !c.enabled {
		return nil
	}
	return fmt.Errorf("eBPF is only supported on Linux")
}

// Stop cleans up and stops the eBPF collector
func (c *EBPFCollector) Stop() {
	// No-op on non-Linux platforms
}

// SetEnabled sets whether eBPF collection is enabled
func (c *EBPFCollector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

// IsEnabled returns whether eBPF collection is enabled
func (c *EBPFCollector) IsEnabled() bool {
	return false // Always false on non-Linux platforms
}

// GetProcessMetrics returns the collected process metrics
func (c *EBPFCollector) GetProcessMetrics() map[int]types.ProcessNetwork {
	// Return empty map on non-Linux platforms
	return make(map[int]types.ProcessNetwork)
}

// GetEvents returns the event channel
func (c *EBPFCollector) GetEvents() <-chan NetworkEvent {
	return c.events
}

// FormatNetworkEvent formats a network event for display (stub for non-Linux)
func FormatNetworkEvent(event *NetworkEvent) string {
	return "eBPF events not available on this platform"
}