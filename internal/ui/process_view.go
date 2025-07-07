package ui

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/nozo-moto/network-monitor/pkg/types"
)

type ProcessView struct {
	app         *tview.Application
	pages       *tview.Pages
	grid        *tview.Grid
	processList *tview.Table
	connTable   *tview.Table
	statsPanel  *tview.TextView
	graphPanel  *tview.TextView
	metrics     types.NetworkMetrics
	selectedPID int
	filter      string
}

func NewProcessView(app *tview.Application) *ProcessView {
	pv := &ProcessView{
		app:         app,
		pages:       tview.NewPages(),
		processList: tview.NewTable(),
		connTable:   tview.NewTable(),
		statsPanel:  tview.NewTextView(),
		graphPanel:  tview.NewTextView(),
	}

	pv.setupUI()
	return pv
}

func (pv *ProcessView) setupUI() {
	// Process list configuration
	pv.processList.SetBorders(true).SetTitle(" Processes (↑↓ to select, Enter to filter) ")
	pv.processList.SetSelectable(true, false)
	pv.processList.SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorDarkBlue))

	// Connection table configuration
	pv.connTable.SetBorders(true).SetTitle(" Process Connections ")
	pv.connTable.SetFixed(1, 0)

	// Stats panel configuration
	pv.statsPanel.SetBorder(true).SetTitle(" Process Network Stats ")
	pv.statsPanel.SetDynamicColors(true)

	// Graph panel configuration
	pv.graphPanel.SetBorder(true).SetTitle(" Process Traffic Graph ")
	pv.graphPanel.SetDynamicColors(true)

	// Create grid layout
	pv.grid = tview.NewGrid().
		SetRows(0, 0).
		SetColumns(40, 0).
		AddItem(pv.processList, 0, 0, 2, 1, 0, 0, true).
		AddItem(pv.connTable, 0, 1, 1, 1, 0, 0, false).
		AddItem(tview.NewGrid().
			SetRows(0, 0).
			SetColumns(0).
			AddItem(pv.statsPanel, 0, 0, 1, 1, 0, 0, false).
			AddItem(pv.graphPanel, 1, 0, 1, 1, 0, 0, false),
			1, 1, 1, 1, 0, 0, false)

	// Setup event handlers
	pv.setupEventHandlers()

	// Add to pages
	pv.pages.AddPage("process", pv.grid, true, true)
}

func (pv *ProcessView) setupEventHandlers() {
	pv.processList.SetSelectedFunc(func(row, column int) {
		if row > 0 {
			pidStr := pv.processList.GetCell(row, 0).Text
			pid, err := strconv.Atoi(pidStr)
			if err == nil {
				pv.selectedPID = pid
				pv.updateProcessDetails()
			}
		}
	})

	pv.processList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			// Return to main dashboard
			return tcell.NewEventKey(tcell.KeyCtrlC, 'c', tcell.ModCtrl)
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				// Return to main dashboard
				return tcell.NewEventKey(tcell.KeyCtrlC, 'c', tcell.ModCtrl)
			case '/':
				// Filter processes
				pv.showFilterDialog()
				return nil
			}
		}
		return event
	})
}

func (pv *ProcessView) showFilterDialog() {
	input := tview.NewInputField().
		SetLabel("Filter processes: ").
		SetFieldWidth(30).
		SetText(pv.filter)
	
	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			pv.filter = input.GetText()
			pv.updateProcessList()
		}
		pv.pages.RemovePage("filter")
	})

	form := tview.NewForm().
		AddFormItem(input).
		SetBorder(true).
		SetTitle(" Filter Processes ").
		SetTitleAlign(tview.AlignCenter)

	pv.pages.AddPage("filter", form, true, true)
	pv.app.SetFocus(input)
}

func (pv *ProcessView) Update(metrics types.NetworkMetrics) {
	pv.metrics = metrics
	pv.updateProcessList()
	if pv.selectedPID > 0 {
		pv.updateProcessDetails()
	}
}

func (pv *ProcessView) updateProcessList() {
	pv.processList.Clear()

	// Header
	headers := []string{"PID", "Name", "In (MB/s)", "Out (MB/s)", "Conns"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold).
			SetAlign(tview.AlignCenter)
		pv.processList.SetCell(0, col, cell)
	}

	// Process data
	processes := make([]types.ProcessNetwork, 0, len(pv.metrics.ProcessNetworks))
	for _, proc := range pv.metrics.ProcessNetworks {
		if pv.filter == "" || 
			fmt.Sprintf("%d", proc.PID) == pv.filter ||
			contains(proc.Name, pv.filter) {
			processes = append(processes, proc)
		}
	}

	// Sort by total traffic
	sort.Slice(processes, func(i, j int) bool {
		totalI := processes[i].BytesRecv + processes[i].BytesSent
		totalJ := processes[j].BytesRecv + processes[j].BytesSent
		return totalI > totalJ
	})

	// Add rows
	for i, proc := range processes {
		row := i + 1
		
		pv.processList.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", proc.PID)))
		pv.processList.SetCell(row, 1, tview.NewTableCell(proc.Name))
		pv.processList.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%.2f", float64(proc.BytesRecv)/1024/1024)))
		pv.processList.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%.2f", float64(proc.BytesSent)/1024/1024)))
		pv.processList.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d", proc.ConnectionCount)))
	}

	// Select first process if none selected
	if pv.selectedPID == 0 && pv.processList.GetRowCount() > 1 {
		pv.processList.Select(1, 0)
	}
}

func (pv *ProcessView) updateProcessDetails() {
	// Update connections table
	pv.updateConnectionsTable()
	
	// Update stats panel
	pv.updateStatsPanel()
	
	// Update traffic graph
	pv.updateTrafficGraph()
}

func (pv *ProcessView) updateConnectionsTable() {
	pv.connTable.Clear()

	// Header
	headers := []string{"Protocol", "Local", "Remote", "State", "Duration"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold)
		pv.connTable.SetCell(0, col, cell)
	}

	// Filter connections for selected process
	row := 1
	for _, conn := range pv.metrics.Connections {
		if conn.PID == uint32(pv.selectedPID) {
			pv.connTable.SetCell(row, 0, tview.NewTableCell(conn.Type))
			pv.connTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%s:%d", conn.LocalAddr, conn.LocalPort)))
			pv.connTable.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%s:%d", conn.RemoteAddr, conn.RemotePort)))
			pv.connTable.SetCell(row, 3, tview.NewTableCell(conn.State))
			pv.connTable.SetCell(row, 4, tview.NewTableCell("-")) // Duration placeholder
			row++
		}
	}
}

func (pv *ProcessView) updateStatsPanel() {
	var proc *types.ProcessNetwork
	for _, p := range pv.metrics.ProcessNetworks {
		if p.PID == pv.selectedPID {
			proc = &p
			break
		}
	}

	if proc == nil {
		pv.statsPanel.SetText("No process selected")
		return
	}

	stats := fmt.Sprintf(`[yellow]Process:[white] %s (PID: %d)

[yellow]Network I/O:[white]
  Received:  %s (%.2f MB/s)
  Sent:      %s (%.2f MB/s)
  Total:     %s

[yellow]Connections:[white]
  Active:    %d
  Listening: %d
  Time Wait: %d

[yellow]Packets:[white]
  In:  %d
  Out: %d

[yellow]Errors:[white]
  In:  %d
  Out: %d`,
		proc.Name, proc.PID,
		formatBytesProcess(proc.BytesRecv), float64(proc.BytesRecv)/1024/1024,
		formatBytesProcess(proc.BytesSent), float64(proc.BytesSent)/1024/1024,
		formatBytesProcess(proc.BytesRecv+proc.BytesSent),
		proc.ConnectionCount, 0, 0, // Placeholder for connection states
		0, 0, // Placeholder for packets
		0, 0, // Placeholder for errors
	)

	pv.statsPanel.SetText(stats)
}

func (pv *ProcessView) updateTrafficGraph() {
	// Simple ASCII graph for process traffic
	graph := `
[green]Download ▼[white] |████████████████░░░░░░░░░░░░| 64%
[red]Upload   ▲[white] |██████░░░░░░░░░░░░░░░░░░░░░░| 20%

Time: ← 60s ─────────────────────────── Now →
`
	pv.graphPanel.SetText(graph)
}

func (pv *ProcessView) GetPages() *tview.Pages {
	return pv.pages
}

func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || contains(s[1:], substr) || contains(s[:len(s)-1], substr))
}

func formatBytesProcess(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}