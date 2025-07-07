package security

import (
	"fmt"
	"sync"
	"time"
)

// SecurityAlert represents a security event
type SecurityAlert struct {
	Timestamp   time.Time
	Type        AlertType
	Severity    Severity
	SourceIP    string
	TargetIP    string
	Description string
	Details     map[string]interface{}
}

type AlertType string

const (
	AlertTypePortScan        AlertType = "PORT_SCAN"
	AlertTypeHighConnections AlertType = "HIGH_CONNECTIONS"
	AlertTypeSuspiciousIP    AlertType = "SUSPICIOUS_IP"
	AlertTypeNewConnection   AlertType = "NEW_CONNECTION"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// SecurityDetector monitors for security threats
type SecurityDetector struct {
	mu sync.RWMutex
	
	// Connection tracking
	connectionCounts map[string]int
	connectionTimes  map[string][]time.Time
	knownIPs        map[string]time.Time
	
	// Port scan detection
	portAccess      map[string]map[int]time.Time // IP -> Port -> Time
	scanWindow      time.Duration
	scanThreshold   int
	
	// Thresholds
	maxConnectionsPerIP int
	alertChannel       chan SecurityAlert
	
	// Statistics
	totalAlerts    int
	alertsByType   map[AlertType]int
}

func NewSecurityDetector() *SecurityDetector {
	return &SecurityDetector{
		connectionCounts:    make(map[string]int),
		connectionTimes:     make(map[string][]time.Time),
		knownIPs:           make(map[string]time.Time),
		portAccess:         make(map[string]map[int]time.Time),
		scanWindow:         10 * time.Second,
		scanThreshold:      10, // 10 different ports in 10 seconds
		maxConnectionsPerIP: 50,
		alertChannel:       make(chan SecurityAlert, 100),
		alertsByType:       make(map[AlertType]int),
	}
}

// AnalyzeConnection checks a connection for security issues
func (sd *SecurityDetector) AnalyzeConnection(localAddr, remoteAddr string, port int) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	
	now := time.Now()
	remoteIP := extractIPFromAddr(remoteAddr)
	
	// Track connection count
	sd.connectionCounts[remoteIP]++
	
	// Track connection times
	if sd.connectionTimes[remoteIP] == nil {
		sd.connectionTimes[remoteIP] = make([]time.Time, 0)
	}
	sd.connectionTimes[remoteIP] = append(sd.connectionTimes[remoteIP], now)
	
	// Clean old connection times (keep last minute only)
	sd.cleanOldConnectionTimes(remoteIP, now)
	
	// Check for new IP
	if _, known := sd.knownIPs[remoteIP]; !known {
		sd.knownIPs[remoteIP] = now
		sd.sendAlert(SecurityAlert{
			Timestamp:   now,
			Type:        AlertTypeNewConnection,
			Severity:    SeverityInfo,
			SourceIP:    remoteIP,
			TargetIP:    localAddr,
			Description: fmt.Sprintf("New connection from %s", remoteIP),
			Details: map[string]interface{}{
				"first_seen": now,
			},
		})
	}
	
	// Check for too many connections
	if sd.connectionCounts[remoteIP] > sd.maxConnectionsPerIP {
		sd.sendAlert(SecurityAlert{
			Timestamp:   now,
			Type:        AlertTypeHighConnections,
			Severity:    SeverityWarning,
			SourceIP:    remoteIP,
			TargetIP:    localAddr,
			Description: fmt.Sprintf("High number of connections from %s: %d", remoteIP, sd.connectionCounts[remoteIP]),
			Details: map[string]interface{}{
				"connection_count": sd.connectionCounts[remoteIP],
				"threshold":        sd.maxConnectionsPerIP,
			},
		})
	}
	
	// Port scan detection
	sd.detectPortScan(remoteIP, port, now)
}

func (sd *SecurityDetector) detectPortScan(ip string, port int, now time.Time) {
	// Initialize port map for IP if needed
	if sd.portAccess[ip] == nil {
		sd.portAccess[ip] = make(map[int]time.Time)
	}
	
	// Record port access
	sd.portAccess[ip][port] = now
	
	// Clean old port accesses
	cutoff := now.Add(-sd.scanWindow)
	for p, t := range sd.portAccess[ip] {
		if t.Before(cutoff) {
			delete(sd.portAccess[ip], p)
		}
	}
	
	// Check if threshold exceeded
	if len(sd.portAccess[ip]) >= sd.scanThreshold {
		// Calculate scan rate
		scanRate := float64(len(sd.portAccess[ip])) / sd.scanWindow.Seconds()
		
		sd.sendAlert(SecurityAlert{
			Timestamp:   now,
			Type:        AlertTypePortScan,
			Severity:    SeverityCritical,
			SourceIP:    ip,
			Description: fmt.Sprintf("Possible port scan detected from %s", ip),
			Details: map[string]interface{}{
				"ports_scanned": len(sd.portAccess[ip]),
				"time_window":   sd.scanWindow.String(),
				"scan_rate":     fmt.Sprintf("%.2f ports/sec", scanRate),
			},
		})
		
		// Reset to prevent duplicate alerts
		sd.portAccess[ip] = make(map[int]time.Time)
	}
}

func (sd *SecurityDetector) cleanOldConnectionTimes(ip string, now time.Time) {
	cutoff := now.Add(-1 * time.Minute)
	newTimes := make([]time.Time, 0)
	
	for _, t := range sd.connectionTimes[ip] {
		if t.After(cutoff) {
			newTimes = append(newTimes, t)
		}
	}
	
	sd.connectionTimes[ip] = newTimes
}

func (sd *SecurityDetector) sendAlert(alert SecurityAlert) {
	sd.totalAlerts++
	sd.alertsByType[alert.Type]++
	
	select {
	case sd.alertChannel <- alert:
	default:
		// Channel full, drop oldest alert
		select {
		case <-sd.alertChannel:
			sd.alertChannel <- alert
		default:
		}
	}
}

// GetAlertChannel returns the channel for receiving alerts
func (sd *SecurityDetector) GetAlertChannel() <-chan SecurityAlert {
	return sd.alertChannel
}

// GetStats returns security statistics
func (sd *SecurityDetector) GetStats() map[string]interface{} {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	
	return map[string]interface{}{
		"total_alerts":    sd.totalAlerts,
		"alerts_by_type":  sd.alertsByType,
		"tracked_ips":     len(sd.knownIPs),
		"active_scanners": len(sd.portAccess),
	}
}

// Helper function to extract IP from address string
func extractIPFromAddr(addr string) string {
	// Simple extraction, assumes format "IP:Port"
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}