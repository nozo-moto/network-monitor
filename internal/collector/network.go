package collector

import (
	"fmt"
	"time"

	"github.com/nozo-moto/network-monitor/pkg/types"
	psnet "github.com/shirou/gopsutil/v3/net"
)

type NetworkCollector struct {
	lastStats map[string]psnet.IOCountersStat
}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		lastStats: make(map[string]psnet.IOCountersStat),
	}
}

func (nc *NetworkCollector) Collect() ([]*types.NetworkStats, error) {
	counters, err := psnet.IOCounters(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get network counters: %w", err)
	}

	var stats []*types.NetworkStats
	now := time.Now()

	for _, counter := range counters {
		if counter.Name == "lo" || counter.Name == "lo0" {
			continue
		}

		stat := &types.NetworkStats{
			Interface:   counter.Name,
			BytesRecv:   counter.BytesRecv,
			BytesSent:   counter.BytesSent,
			PacketsRecv: counter.PacketsRecv,
			PacketsSent: counter.PacketsSent,
			Errin:       counter.Errin,
			Errout:      counter.Errout,
			Dropin:      counter.Dropin,
			Dropout:     counter.Dropout,
			Timestamp:   now,
		}

		stats = append(stats, stat)
		nc.lastStats[counter.Name] = counter
	}

	return stats, nil
}

func (nc *NetworkCollector) GetConnections() ([]types.ConnectionInfo, error) {
	conns, err := psnet.Connections("tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	var connInfo []types.ConnectionInfo
	for _, conn := range conns {
		if conn.Status == "LISTEN" {
			continue
		}

		info := types.ConnectionInfo{
			LocalAddr:  fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port),
			State:      conn.Status,
			Type:       "TCP",
		}
		connInfo = append(connInfo, info)
	}

	return connInfo, nil
}

func (nc *NetworkCollector) GetActiveInterfaces() ([]string, error) {
	interfaces, err := psnet.Interfaces()
	if err != nil {
		return nil, err
	}

	var active []string
	for _, iface := range interfaces {
		if iface.Name != "lo" && iface.Name != "lo0" {
			active = append(active, iface.Name)
		}
	}

	return active, nil
}