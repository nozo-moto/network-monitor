//go:build linux
// +build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/nozo-moto/network-monitor/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -tags linux netmon ./bpf/netmon.c

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

type EBPFCollector struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *perf.Reader
	events     chan NetworkEvent
	metrics    map[int]types.ProcessNetwork
	enabled    bool
}

func NewEBPFCollector() (*EBPFCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	return &EBPFCollector{
		events:  make(chan NetworkEvent, 100),
		metrics: make(map[int]types.ProcessNetwork),
		enabled: false,
	}, nil
}

// loadNetmon is a placeholder for the generated function
// In a real implementation, this would be generated by bpf2go
func loadNetmon() (*ebpf.CollectionSpec, error) {
	// This is a stub - in production, this would load the compiled BPF program
	return nil, fmt.Errorf("BPF program not compiled - run go generate")
}

func (c *EBPFCollector) Start() error {
	if !c.enabled {
		return nil
	}

	// Load pre-compiled BPF program
	spec, err := loadNetmon()
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}
	c.collection = coll

	// Attach to network hooks
	if err := c.attachPrograms(); err != nil {
		c.collection.Close()
		return fmt.Errorf("failed to attach BPF programs: %w", err)
	}

	// Open perf event reader
	reader, err := perf.NewReader(c.collection.Maps["events"], 4096)
	if err != nil {
		c.cleanup()
		return fmt.Errorf("failed to create perf reader: %w", err)
	}
	c.reader = reader

	// Start event processing
	go c.processEvents()

	return nil
}

func (c *EBPFCollector) attachPrograms() error {
	// Attach to TC ingress
	ingressProg := c.collection.Programs["tc_ingress"]
	if ingressProg != nil {
		// Note: Actual TC attachment requires more setup with netlink
		// This is a simplified version
		log.Printf("TC ingress program loaded")
	}

	// Attach to TC egress
	egressProg := c.collection.Programs["tc_egress"]
	if egressProg != nil {
		log.Printf("TC egress program loaded")
	}

	// Attach to socket operations
	sockProg := c.collection.Programs["socket_monitor"]
	if sockProg != nil {
		// Note: The actual attachment would require specific kernel support
		// This is a simplified version for demonstration
		log.Printf("Socket monitor program loaded")
	}

	return nil
}

func (c *EBPFCollector) processEvents() {
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("error reading from perf buffer: %v", err)
			continue
		}

		var event NetworkEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		// Update metrics
		c.updateMetrics(&event)

		// Send to channel for real-time updates
		select {
		case c.events <- event:
		default:
			// Drop event if channel is full
		}
	}
}

func (c *EBPFCollector) updateMetrics(event *NetworkEvent) {
	pid := int(event.PID)
	
	metric, exists := c.metrics[pid]
	if !exists {
		metric = types.ProcessNetwork{
			PID:  pid,
			Name: string(bytes.TrimRight(event.Comm[:], "\x00")),
		}
	}

	if event.Direction == 0 { // Ingress
		metric.BytesRecv += uint64(event.Size)
	} else { // Egress
		metric.BytesSent += uint64(event.Size)
	}

	c.metrics[pid] = metric
}

func (c *EBPFCollector) GetProcessMetrics() map[int]types.ProcessNetwork {
	// Return a copy to avoid race conditions
	result := make(map[int]types.ProcessNetwork)
	for k, v := range c.metrics {
		result[k] = v
	}
	return result
}

func (c *EBPFCollector) GetEvents() <-chan NetworkEvent {
	return c.events
}

func (c *EBPFCollector) cleanup() {
	for _, l := range c.links {
		l.Close()
	}
	if c.reader != nil {
		c.reader.Close()
	}
	if c.collection != nil {
		c.collection.Close()
	}
}

func (c *EBPFCollector) Stop() {
	c.cleanup()
}

func (c *EBPFCollector) SetEnabled(enabled bool) {
	c.enabled = enabled
}

func (c *EBPFCollector) IsEnabled() bool {
	return c.enabled
}

// Helper function to format network event
func FormatNetworkEvent(event *NetworkEvent) string {
	srcIP := net.IPv4(byte(event.SAddr), byte(event.SAddr>>8), byte(event.SAddr>>16), byte(event.SAddr>>24))
	dstIP := net.IPv4(byte(event.DAddr), byte(event.DAddr>>8), byte(event.DAddr>>16), byte(event.DAddr>>24))
	
	direction := "RX"
	if event.Direction == 1 {
		direction = "TX"
	}
	
	return fmt.Sprintf("[%s] PID=%d (%s) %s:%d -> %s:%d Size=%d",
		direction,
		event.PID,
		string(bytes.TrimRight(event.Comm[:], "\x00")),
		srcIP, event.SPort,
		dstIP, event.DPort,
		event.Size,
	)
}