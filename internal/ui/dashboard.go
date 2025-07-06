package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/nozo-moto/network-monitor/internal/collector"
	"github.com/nozo-moto/network-monitor/pkg/types"
	"github.com/rivo/tview"
)

type Dashboard struct {
	app              *tview.Application
	networkCollector *collector.NetworkCollector
	systemCollector  *collector.SystemCollector
	processCollector *collector.ProcessCollector
	latencyCollector *collector.LatencyCollector
	
	dateTimeView    *tview.TextView
	systemInfo      *tview.TextView
	networkInfo     *tview.TextView
	connectionsList *tview.TextView
	flowStatsView   *tview.TextView
	historyView     *tview.TextView
	processView     *tview.TextView
	latencyView     *tview.TextView
	
	metrics         *types.Metrics
	mu              sync.RWMutex
	updateInterval  time.Duration
	
	// For tracking connection history
	activeConns     map[string]time.Time
	historyMu       sync.RWMutex
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		app:              tview.NewApplication(),
		networkCollector: collector.NewNetworkCollector(),
		systemCollector:  collector.NewSystemCollector(),
		processCollector: collector.NewProcessCollector(),
		latencyCollector: collector.NewLatencyCollector(),
		metrics:         &types.Metrics{
			FlowStats:      make(map[string]*types.NetworkFlowStats),
			ConnHistory:    make([]types.ConnectionHistory, 0),
			TrafficHistory: make([]types.TrafficDataPoint, 0),
			ProcessStats:   make([]types.ProcessNetworkStats, 0),
			LatencyStats:   make([]types.LatencyStats, 0),
		},
		updateInterval:  time.Second,
		activeConns:     make(map[string]time.Time),
	}
}

func (d *Dashboard) Run() error {
	d.setupUI()
	
	go d.updateLoop()
	
	return d.app.Run()
}

func (d *Dashboard) setupUI() {
	// Date/Time view at the top
	d.dateTimeView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	d.dateTimeView.SetBorder(true).
		SetTitle(" Current Date & Time ")
	
	d.systemInfo = tview.NewTextView().
		SetDynamicColors(true)
	d.systemInfo.SetBorder(true).
		SetTitle(" System Metrics ")
	
	d.networkInfo = tview.NewTextView().
		SetDynamicColors(true)
	d.networkInfo.SetBorder(true).
		SetTitle(" Network Stats ")
	
	d.connectionsList = tview.NewTextView().
		SetDynamicColors(true)
	d.connectionsList.SetBorder(true).
		SetTitle(" Active Connections ")
	
	d.flowStatsView = tview.NewTextView().
		SetDynamicColors(true)
	d.flowStatsView.SetBorder(true).
		SetTitle(" Network Flow Statistics ")
	
	d.processView = tview.NewTextView().
		SetDynamicColors(true)
	d.processView.SetBorder(true).
		SetTitle(" Process Network Usage ")
	
	d.latencyView = tview.NewTextView().
		SetDynamicColors(true)
	d.latencyView.SetBorder(true).
		SetTitle(" Network Latency ")
	
	d.historyView = tview.NewTextView().
		SetDynamicColors(true)
	d.historyView.SetBorder(true).
		SetTitle(" Traffic Volume Graph ")
	
	// Left column
	leftColumn := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(d.systemInfo, 8, 1, false).
		AddItem(d.networkInfo, 10, 1, false).
		AddItem(d.latencyView, 0, 1, false)
	
	// Middle column
	middleColumn := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(d.connectionsList, 0, 1, false).
		AddItem(d.flowStatsView, 0, 1, false)
	
	// Right column
	rightColumn := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(d.processView, 0, 1, false)
	
	// Top section with three columns
	topSection := tview.NewFlex().
		AddItem(leftColumn, 35, 1, false).
		AddItem(middleColumn, 45, 1, false).
		AddItem(rightColumn, 0, 1, false)
	
	// Main layout with date/time at top, panels in middle, history at bottom
	mainFlex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(d.dateTimeView, 3, 1, false).
		AddItem(topSection, 0, 1, false).
		AddItem(d.historyView, 0, 1, false)
	
	d.app.SetRoot(mainFlex, true).
		SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyEsc || event.Rune() == 'q' {
				d.app.Stop()
			}
			return event
		})
}

func (d *Dashboard) updateLoop() {
	ticker := time.NewTicker(d.updateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			d.collectMetrics()
			d.updateDisplay()
		}
	}
}

func (d *Dashboard) collectMetrics() {
	now := time.Now()
	
	sysStats, err := d.systemCollector.Collect()
	if err == nil {
		d.mu.Lock()
		d.metrics.System = sysStats
		d.mu.Unlock()
	}
	
	netStats, err := d.networkCollector.Collect()
	if err == nil && len(netStats) > 0 {
		d.mu.Lock()
		d.metrics.Network = netStats[0]
		d.mu.Unlock()
	}
	
	conns, err := d.networkCollector.GetConnections()
	if err == nil {
		d.mu.Lock()
		d.metrics.Conns = conns
		d.metrics.CurrentTime = now
		d.mu.Unlock()
		
		// Update flow statistics and connection history
		d.updateFlowStats(conns, now)
		d.updateConnectionHistory(conns, now)
		
		// Collect traffic history data point
		d.collectTrafficHistory(now)
	}
	
	// Collect process network stats
	processStats, err := d.processCollector.Collect()
	if err == nil {
		d.mu.Lock()
		d.metrics.ProcessStats = processStats
		d.mu.Unlock()
	}
	
	// Collect latency stats (less frequently to avoid overload)
	if now.Second()%5 == 0 { // Every 5 seconds
		latencyStats, err := d.latencyCollector.Collect()
		if err == nil {
			d.mu.Lock()
			d.metrics.LatencyStats = latencyStats
			d.mu.Unlock()
		}
	}
}

func (d *Dashboard) updateDisplay() {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	d.app.QueueUpdateDraw(func() {
		d.updateDateTime()
		d.updateSystemInfo()
		d.updateNetworkInfo()
		d.updateConnectionsList()
		d.updateFlowStatsView()
		d.updateProcessView()
		d.updateLatencyView()
		d.updateHistoryView()
	})
}

func (d *Dashboard) updateSystemInfo() {
	if d.metrics.System == nil {
		return
	}
	
	s := d.metrics.System
	text := fmt.Sprintf(
		"[yellow]CPU Usage:[white] %.2f%%\n"+
		"[yellow]Memory:[white] %s / %s (%.1f%%)\n"+
		"[yellow]Connections:[white] %d\n"+
		"[yellow]Goroutines:[white] %d\n"+
		"[yellow]Updated:[white] %s",
		s.CPUPercent,
		formatBytes(s.MemoryUsed),
		formatBytes(s.MemoryTotal),
		s.MemoryPerc,
		s.Connections,
		s.Goroutines,
		s.Timestamp.Format("15:04:05"),
	)
	
	d.systemInfo.SetText(text)
}

func (d *Dashboard) updateNetworkInfo() {
	if d.metrics.Network == nil {
		return
	}
	
	n := d.metrics.Network
	text := fmt.Sprintf(
		"[yellow]Interface:[white] %s\n\n"+
		"[green]▼ Received[white]\n"+
		"  Bytes: %s\n"+
		"  Packets: %s\n"+
		"  Errors: %d\n"+
		"  Dropped: %d\n\n"+
		"[red]▲ Sent[white]\n"+
		"  Bytes: %s\n"+
		"  Packets: %s\n"+
		"  Errors: %d\n"+
		"  Dropped: %d",
		n.Interface,
		formatBytes(n.BytesRecv),
		formatNumber(n.PacketsRecv),
		n.Errin,
		n.Dropin,
		formatBytes(n.BytesSent),
		formatNumber(n.PacketsSent),
		n.Errout,
		n.Dropout,
	)
	
	d.networkInfo.SetText(text)
}

func (d *Dashboard) updateConnectionsList() {
	if len(d.metrics.Conns) == 0 {
		d.connectionsList.SetText("[gray]No active connections")
		return
	}
	
	var builder strings.Builder
	builder.WriteString("[yellow]Local Address -> Remote Address (State)[white]\n")
	builder.WriteString(strings.Repeat("─", 55) + "\n")
	
	for i, conn := range d.metrics.Conns {
		if i >= 20 {
			builder.WriteString(fmt.Sprintf("\n[gray]... and %d more connections", len(d.metrics.Conns)-20))
			break
		}
		
		color := "[white]"
		if conn.State == "ESTABLISHED" {
			color = "[green]"
		} else if conn.State == "TIME_WAIT" {
			color = "[yellow]"
		} else if conn.State == "CLOSE_WAIT" {
			color = "[red]"
		}
		
		builder.WriteString(fmt.Sprintf("%s%-25s -> %-25s (%s)[white]\n",
			color,
			conn.LocalAddr,
			conn.RemoteAddr,
			conn.State,
		))
	}
	
	d.connectionsList.SetText(builder.String())
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fG", float64(n)/1000000000)
}

func (d *Dashboard) updateDateTime() {
	text := fmt.Sprintf("[cyan]%s[white]", d.metrics.CurrentTime.Format("2006-01-02 15:04:05"))
	d.dateTimeView.SetText(text)
}

func (d *Dashboard) updateFlowStats(conns []types.ConnectionInfo, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	for _, conn := range conns {
		if conn.State == "ESTABLISHED" {
			key := fmt.Sprintf("%s->%s", conn.LocalAddr, conn.RemoteAddr)
			
			if flow, exists := d.metrics.FlowStats[key]; exists {
				flow.LastSeen = now
				flow.PacketCount++
				// Simulate traffic volume based on connection activity
				flow.BytesSent += uint64(1024 + (flow.PacketCount%100)*512)
				flow.BytesReceived += uint64(2048 + (flow.PacketCount%50)*1024)
			} else {
				d.metrics.FlowStats[key] = &types.NetworkFlowStats{
					SourceIP:      conn.LocalAddr,
					DestIP:        conn.RemoteAddr,
					FirstSeen:     now,
					LastSeen:      now,
					PacketCount:   1,
					BytesSent:     1024,
					BytesReceived: 2048,
				}
			}
		}
	}
}

func (d *Dashboard) updateConnectionHistory(conns []types.ConnectionInfo, now time.Time) {
	d.historyMu.Lock()
	defer d.historyMu.Unlock()
	
	// Track current connections
	currentConns := make(map[string]bool)
	for _, conn := range conns {
		key := fmt.Sprintf("%s->%s", conn.LocalAddr, conn.RemoteAddr)
		currentConns[key] = true
		
		// If this is a new connection, track it
		if _, exists := d.activeConns[key]; !exists {
			d.activeConns[key] = now
		}
	}
	
	// Check for closed connections
	for key, startTime := range d.activeConns {
		if !currentConns[key] {
			// Connection closed, add to history
			parts := strings.Split(key, "->")
			if len(parts) == 2 {
				endTime := now
				hist := types.ConnectionHistory{
					LocalAddr:  parts[0],
					RemoteAddr: parts[1],
					StartTime:  startTime,
					EndTime:    &endTime,
					Duration:   now.Sub(startTime),
				}
				
				d.mu.Lock()
				d.metrics.ConnHistory = append(d.metrics.ConnHistory, hist)
				// Keep only last 100 entries
				if len(d.metrics.ConnHistory) > 100 {
					d.metrics.ConnHistory = d.metrics.ConnHistory[len(d.metrics.ConnHistory)-100:]
				}
				d.mu.Unlock()
			}
			delete(d.activeConns, key)
		}
	}
}

func (d *Dashboard) updateFlowStatsView() {
	if len(d.metrics.FlowStats) == 0 {
		d.flowStatsView.SetText("[gray]No flow statistics available")
		return
	}
	
	var builder strings.Builder
	builder.WriteString("[yellow]Source → Destination (Packets | Duration)[white]\n")
	builder.WriteString(strings.Repeat("─", 70) + "\n")
	
	// Sort flows by packet count
	type flowEntry struct {
		key   string
		stats *types.NetworkFlowStats
	}
	flows := make([]flowEntry, 0, len(d.metrics.FlowStats))
	for k, v := range d.metrics.FlowStats {
		flows = append(flows, flowEntry{k, v})
	}
	
	// Sort by packet count descending
	for i := 0; i < len(flows)-1; i++ {
		for j := i + 1; j < len(flows); j++ {
			if flows[j].stats.PacketCount > flows[i].stats.PacketCount {
				flows[i], flows[j] = flows[j], flows[i]
			}
		}
	}
	
	for i, flow := range flows {
		if i >= 10 {
			builder.WriteString(fmt.Sprintf("\n[gray]... and %d more flows", len(flows)-10))
			break
		}
		
		duration := flow.stats.LastSeen.Sub(flow.stats.FirstSeen)
		builder.WriteString(fmt.Sprintf("%-30s → %-30s (%6d | %s)\n",
			flow.stats.SourceIP,
			flow.stats.DestIP,
			flow.stats.PacketCount,
			formatDuration(duration),
		))
	}
	
	d.flowStatsView.SetText(builder.String())
}

func (d *Dashboard) collectTrafficHistory(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Calculate current traffic volumes
	bytesIn := uint64(0)
	bytesOut := uint64(0)
	
	if d.metrics.Network != nil {
		bytesIn = d.metrics.Network.BytesRecv
		bytesOut = d.metrics.Network.BytesSent
	}
	
	dataPoint := types.TrafficDataPoint{
		Time:        now,
		BytesIn:     bytesIn,
		BytesOut:    bytesOut,
		Connections: len(d.metrics.Conns),
	}
	
	d.metrics.TrafficHistory = append(d.metrics.TrafficHistory, dataPoint)
	
	// Keep only last 60 data points (60 seconds of history)
	if len(d.metrics.TrafficHistory) > 60 {
		d.metrics.TrafficHistory = d.metrics.TrafficHistory[len(d.metrics.TrafficHistory)-60:]
	}
}

func (d *Dashboard) updateHistoryView() {
	if len(d.metrics.TrafficHistory) < 2 {
		d.historyView.SetText("[gray]Collecting traffic data...")
		return
	}
	
	var builder strings.Builder
	builder.WriteString("[yellow]Network Traffic History (Last 60 seconds)[white]\n")
	builder.WriteString(strings.Repeat("─", 120) + "\n\n")
	
	// Prepare data for line graph
	history := d.metrics.TrafficHistory
	graphHeight := 25  // Increased height
	graphWidth := 100  // Increased width
	
	// Find max values for scaling
	maxBytes := uint64(0)
	for i := 1; i < len(history); i++ {
		// Calculate bytes per second (delta)
		deltaIn := uint64(0)
		deltaOut := uint64(0)
		if history[i].BytesIn > history[i-1].BytesIn {
			deltaIn = history[i].BytesIn - history[i-1].BytesIn
		}
		if history[i].BytesOut > history[i-1].BytesOut {
			deltaOut = history[i].BytesOut - history[i-1].BytesOut
		}
		
		if deltaIn > maxBytes {
			maxBytes = deltaIn
		}
		if deltaOut > maxBytes {
			maxBytes = deltaOut
		}
	}
	
	// Create the graph grid with space for labels
	leftMargin := 10  // Space for Y-axis labels
	bottomMargin := 2 // Space for X-axis labels
	
	grid := make([][]string, graphHeight+bottomMargin)
	for i := range grid {
		grid[i] = make([]string, graphWidth+leftMargin)
		for j := range grid[i] {
			grid[i][j] = " "
		}
	}
	
	// Draw Y-axis
	for i := 0; i < graphHeight; i++ {
		grid[i][leftMargin] = "│"
	}
	
	// Draw X-axis
	for j := leftMargin; j < graphWidth+leftMargin; j++ {
		grid[graphHeight-1][j] = "─"
	}
	grid[graphHeight-1][leftMargin] = "└"
	
	// Add Y-axis labels
	for i := 0; i <= 4; i++ {
		row := i * (graphHeight-1) / 4
		value := maxBytes * uint64(4-i) / 4
		label := fmt.Sprintf("%7s/s", formatBytes(value))
		for j, ch := range label {
			if j < leftMargin {
				grid[row][j] = string(ch)
			}
		}
	}
	
	// Plot the lines
	if maxBytes > 0 && len(history) > 1 {
		step := float64(graphWidth-5) / float64(len(history)-1)
		
		for i := 1; i < len(history); i++ {
			x := int(float64(i) * step) + leftMargin + 2
			if x >= graphWidth + leftMargin {
				break
			}
			
			// Calculate bytes per second
			deltaIn := uint64(0)
			deltaOut := uint64(0)
			if history[i].BytesIn > history[i-1].BytesIn {
				deltaIn = history[i].BytesIn - history[i-1].BytesIn
			}
			if history[i].BytesOut > history[i-1].BytesOut {
				deltaOut = history[i].BytesOut - history[i-1].BytesOut
			}
			
			// Scale to graph height
			yIn := graphHeight - 2 - int(float64(deltaIn)/float64(maxBytes)*float64(graphHeight-3))
			yOut := graphHeight - 2 - int(float64(deltaOut)/float64(maxBytes)*float64(graphHeight-3))
			
			// Plot points
			if yIn >= 0 && yIn < graphHeight-1 {
				grid[yIn][x] = "[green]▼[white]" // Download (green)
			}
			if yOut >= 0 && yOut < graphHeight-1 {
				grid[yOut][x] = "[red]▲[white]" // Upload (red)
			}
		}
	}
	
	// Add X-axis time labels
	timeLabels := []string{"-60s", "-45s", "-30s", "-15s", "0s"}
	labelPositions := []int{0, 25, 50, 75, 95}
	for i, label := range timeLabels {
		pos := leftMargin + labelPositions[i]
		if pos < len(grid[graphHeight]) - len(label) {
			for j, ch := range label {
				grid[graphHeight][pos+j] = string(ch)
			}
		}
	}
	
	// Draw the graph
	for i := 0; i < graphHeight+bottomMargin; i++ {
		for j := 0; j < graphWidth+leftMargin; j++ {
			builder.WriteString(grid[i][j])
		}
		builder.WriteString("\n")
	}
	
	// Add legend
	builder.WriteString("\n[green]▼ Download[white]  [red]▲ Upload[white]\n")
	
	// Add current stats
	if len(history) >= 2 {
		last := history[len(history)-1]
		prev := history[len(history)-2]
		
		deltaIn := uint64(0)
		deltaOut := uint64(0)
		if last.BytesIn > prev.BytesIn {
			deltaIn = last.BytesIn - prev.BytesIn
		}
		if last.BytesOut > prev.BytesOut {
			deltaOut = last.BytesOut - prev.BytesOut
		}
		
		builder.WriteString(fmt.Sprintf("\n[yellow]Current:[white] Download: [green]%s/s[white]  Upload: [red]%s/s[white]  Connections: [cyan]%d[white]\n",
			formatBytes(deltaIn),
			formatBytes(deltaOut),
			last.Connections,
		))
	}
	
	d.historyView.SetText(builder.String())
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func extractIP(addr string) string {
	// Extract IP address from "IP:Port" format
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

func (d *Dashboard) updateProcessView() {
	if len(d.metrics.ProcessStats) == 0 {
		d.processView.SetText("[gray]No process data available")
		return
	}
	
	var builder strings.Builder
	builder.WriteString("[yellow]Process              Download    Upload     Conns[white]\n")
	builder.WriteString(strings.Repeat("─", 55) + "\n")
	
	// Show top 15 processes by total traffic
	count := 0
	for _, proc := range d.metrics.ProcessStats {
		if count >= 15 {
			break
		}
		
		// Format process name (truncate if too long)
		name := proc.Name
		if len(name) > 20 {
			name = name[:17] + "..."
		}
		
		// Create traffic bar visualization
		totalTraffic := proc.BytesSent + proc.BytesRecv
		maxBarLength := 20
		
		// Calculate bar lengths (proportional to traffic)
		downBar := ""
		upBar := ""
		if totalTraffic > 0 {
			downRatio := float64(proc.BytesRecv) / float64(totalTraffic)
			upRatio := float64(proc.BytesSent) / float64(totalTraffic)
			
			downLength := int(downRatio * float64(maxBarLength))
			upLength := int(upRatio * float64(maxBarLength))
			
			if downLength > 0 {
				downBar = "[green]" + strings.Repeat("▼", downLength) + "[white]"
			}
			if upLength > 0 {
				upBar = "[red]" + strings.Repeat("▲", upLength) + "[white]"
			}
		}
		
		builder.WriteString(fmt.Sprintf("%-20s %8s/s  %8s/s   %3d\n",
			name,
			formatBytes(proc.BytesRecv),
			formatBytes(proc.BytesSent),
			proc.Connections,
		))
		
		// Add visual bar if there's traffic
		if downBar != "" || upBar != "" {
			builder.WriteString(fmt.Sprintf("                     %s%s\n", downBar, upBar))
		}
		
		count++
	}
	
	d.processView.SetText(builder.String())
}

func (d *Dashboard) updateLatencyView() {
	if len(d.metrics.LatencyStats) == 0 {
		d.latencyView.SetText("[gray]Measuring latency...")
		return
	}
	
	var builder strings.Builder
	builder.WriteString("[yellow]Host                 Latency          Loss[white]\n")
	builder.WriteString(strings.Repeat("─", 50) + "\n")
	
	for _, stat := range d.metrics.LatencyStats {
		// Format host name
		host := stat.Host
		if len(host) > 20 {
			host = host[:17] + "..."
		}
		
		// Create latency visualization
		latencyBar := ""
		barLength := 0
		color := "[green]"
		
		avgMs := stat.AvgRTT.Milliseconds()
		if avgMs < 50 {
			color = "[green]"
			barLength = 8
		} else if avgMs < 100 {
			color = "[yellow]"
			barLength = 6
		} else if avgMs < 200 {
			color = "[orange]"
			barLength = 4
		} else {
			color = "[red]"
			barLength = 2
		}
		
		if stat.PacketLoss == 100 {
			color = "[red]"
			barLength = 0
		}
		
		if barLength > 0 {
			latencyBar = color + strings.Repeat("█", barLength) + "[white]"
		}
		
		// Format output
		latencyText := "Timeout"
		if stat.PacketLoss < 100 {
			latencyText = fmt.Sprintf("%3dms", avgMs)
		}
		
		lossText := fmt.Sprintf("%.1f%%", stat.PacketLoss)
		if stat.PacketLoss == 0 {
			lossText = "0%"
		}
		
		// Determine status symbol
		statusSymbol := "✓"
		statusColor := "[green]"
		if stat.PacketLoss == 100 {
			statusSymbol = "✗"
			statusColor = "[red]"
		} else if stat.PacketLoss > 0 || avgMs > 100 {
			statusSymbol = "⚠"
			statusColor = "[yellow]"
		}
		
		builder.WriteString(fmt.Sprintf("%-20s %s %-10s %5s %s%s[white]\n",
			host,
			latencyBar,
			latencyText,
			lossText,
			statusColor,
			statusSymbol,
		))
	}
	
	// Add bandwidth utilization if available
	if d.metrics.Network != nil {
		builder.WriteString("\n[yellow]Bandwidth Utilization[white]\n")
		builder.WriteString(strings.Repeat("─", 50) + "\n")
		
		// Simulate bandwidth capacity (1 Gbps for example)
		// In real implementation, this would be detected from interface
		bandwidthCapacity := uint64(1000 * 1000 * 1000 / 8) // 1 Gbps in bytes
		
		if len(d.metrics.TrafficHistory) >= 2 {
			last := d.metrics.TrafficHistory[len(d.metrics.TrafficHistory)-1]
			prev := d.metrics.TrafficHistory[len(d.metrics.TrafficHistory)-2]
			
			deltaIn := uint64(0)
			deltaOut := uint64(0)
			if last.BytesIn > prev.BytesIn {
				deltaIn = last.BytesIn - prev.BytesIn
			}
			if last.BytesOut > prev.BytesOut {
				deltaOut = last.BytesOut - prev.BytesOut
			}
			
			// Calculate utilization percentage
			inPercent := float64(deltaIn) / float64(bandwidthCapacity) * 100
			outPercent := float64(deltaOut) / float64(bandwidthCapacity) * 100
			
			// Create utilization bars
			maxBarLen := 20
			inBarLen := int(inPercent / 100 * float64(maxBarLen))
			outBarLen := int(outPercent / 100 * float64(maxBarLen))
			
			if inBarLen > maxBarLen {
				inBarLen = maxBarLen
			}
			if outBarLen > maxBarLen {
				outBarLen = maxBarLen
			}
			
			inBar := "[green]" + strings.Repeat("█", inBarLen) + "[gray]" + strings.Repeat("░", maxBarLen-inBarLen) + "[white]"
			outBar := "[red]" + strings.Repeat("█", outBarLen) + "[gray]" + strings.Repeat("░", maxBarLen-outBarLen) + "[white]"
			
			builder.WriteString(fmt.Sprintf("Download: %s %5.1f%% (%s)\n", inBar, inPercent, formatBytes(deltaIn)+"/s"))
			builder.WriteString(fmt.Sprintf("Upload:   %s %5.1f%% (%s)\n", outBar, outPercent, formatBytes(deltaOut)+"/s"))
		}
	}
	
	d.latencyView.SetText(builder.String())
}