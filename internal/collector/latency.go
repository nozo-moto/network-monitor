package collector

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nozo-moto/network-monitor/pkg/types"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type LatencyCollector struct {
	targets []string
	mu      sync.RWMutex
}

func NewLatencyCollector() *LatencyCollector {
	return &LatencyCollector{
		targets: []string{
			"google.com",
			"github.com", 
			"cloudflare.com",
			"1.1.1.1",
			"8.8.8.8",
		},
	}
}

func (lc *LatencyCollector) SetTargets(targets []string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.targets = targets
}

func (lc *LatencyCollector) Collect() ([]types.LatencyStats, error) {
	lc.mu.RLock()
	targets := make([]string, len(lc.targets))
	copy(targets, lc.targets)
	lc.mu.RUnlock()

	var results []types.LatencyStats
	var wg sync.WaitGroup
	resultsChan := make(chan types.LatencyStats, len(targets))

	// Create context with timeout for all measurements
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, target := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			stats := lc.measureLatencyWithContext(ctx, host)
			resultsChan <- stats
		}(target)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for stats := range resultsChan {
		results = append(results, stats)
	}

	return results, nil
}

func (lc *LatencyCollector) measureLatency(host string) types.LatencyStats {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return lc.measureLatencyWithContext(ctx, host)
}

func (lc *LatencyCollector) measureLatencyWithContext(ctx context.Context, host string) types.LatencyStats {
	stats := types.LatencyStats{
		Host:        host,
		LastChecked: time.Now(),
	}

	// Resolve hostname to IP with timeout
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		stats.PacketLoss = 100.0
		return stats
	}
	stats.IP = ips[0].IP.String()

	// Perform multiple pings to calculate statistics
	const pingCount = 3 // Reduced from 4 to speed up
	var rtts []time.Duration
	successCount := 0

	for i := 0; i < pingCount; i++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			// Timeout reached, return what we have
			break
		default:
		}
		
		rtt, err := lc.pingWithTimeout(ips[0].IP.String(), 2*time.Second)
		if err == nil {
			rtts = append(rtts, rtt)
			successCount++
		}
		
		// Only sleep if not the last ping
		if i < pingCount-1 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(50 * time.Millisecond): // Reduced from 100ms
			}
		}
	}

	// Calculate statistics
	if successCount == 0 {
		stats.PacketLoss = 100.0
	} else {
		stats.PacketLoss = float64(pingCount-successCount) / float64(pingCount) * 100.0
		
		// Calculate min, avg, max
		var total time.Duration
		stats.MinRTT = rtts[0]
		stats.MaxRTT = rtts[0]
		
		for _, rtt := range rtts {
			total += rtt
			if rtt < stats.MinRTT {
				stats.MinRTT = rtt
			}
			if rtt > stats.MaxRTT {
				stats.MaxRTT = rtt
			}
		}
		
		stats.AvgRTT = total / time.Duration(len(rtts))
	}

	return stats
}

func (lc *LatencyCollector) ping(dst string) (time.Duration, error) {
	return lc.pingWithTimeout(dst, 5*time.Second)
}

func (lc *LatencyCollector) pingWithTimeout(dst string, timeout time.Duration) (time.Duration, error) {
	// Note: This is a simplified ping implementation
	// Real ICMP ping requires root privileges on most systems
	// For production, consider using a library like github.com/go-ping/ping
	
	// For now, we'll use a simple TCP connection test as a fallback
	start := time.Now()
	conn, err := net.DialTimeout("tcp", dst+":80", timeout)
	if err != nil {
		// Try HTTPS port if HTTP fails
		conn, err = net.DialTimeout("tcp", dst+":443", timeout)
		if err != nil {
			return 0, err
		}
	}
	defer conn.Close()
	
	return time.Since(start), nil
}

// Alternative ICMP ping implementation (requires root/admin privileges)
func (lc *LatencyCollector) icmpPing(dst string) (time.Duration, error) {
	host, err := net.ResolveIPAddr("ip4", dst)
	if err != nil {
		return 0, err
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Create ICMP packet
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("ping"),
		},
	}

	data, err := message.Marshal(nil)
	if err != nil {
		return 0, err
	}

	// Send packet
	start := time.Now()
	_, err = conn.WriteTo(data, host)
	if err != nil {
		return 0, err
	}

	// Receive reply
	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return 0, err
	}

	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, err
	}
	duration := time.Since(start)

	// Parse reply
	replyMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return 0, err
	}

	if replyMsg.Type != ipv4.ICMPTypeEchoReply {
		return 0, fmt.Errorf("expected echo reply, got %v", replyMsg.Type)
	}

	return duration, nil
}