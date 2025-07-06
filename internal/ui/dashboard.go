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
	app             *tview.Application
	networkCollector *collector.NetworkCollector
	systemCollector  *collector.SystemCollector
	
	systemInfo      *tview.TextView
	networkInfo     *tview.TextView
	connectionsList *tview.TextView
	
	metrics         *types.Metrics
	mu              sync.RWMutex
	updateInterval  time.Duration
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		app:             tview.NewApplication(),
		networkCollector: collector.NewNetworkCollector(),
		systemCollector:  collector.NewSystemCollector(),
		metrics:         &types.Metrics{},
		updateInterval:  time.Second,
	}
}

func (d *Dashboard) Run() error {
	d.setupUI()
	
	go d.updateLoop()
	
	return d.app.Run()
}

func (d *Dashboard) setupUI() {
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
	
	leftPanel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(d.systemInfo, 8, 1, false).
		AddItem(d.networkInfo, 0, 1, false)
	
	mainFlex := tview.NewFlex().
		AddItem(leftPanel, 0, 1, false).
		AddItem(d.connectionsList, 60, 1, false)
	
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
		d.mu.Unlock()
	}
}

func (d *Dashboard) updateDisplay() {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	d.app.QueueUpdateDraw(func() {
		d.updateSystemInfo()
		d.updateNetworkInfo()
		d.updateConnectionsList()
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