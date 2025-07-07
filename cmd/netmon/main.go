package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nozo-moto/network-monitor/internal/collector"
	"github.com/nozo-moto/network-monitor/internal/ui"
)

func main() {
	var (
		enableEBPF = flag.Bool("ebpf", false, "Enable eBPF-based network monitoring (requires root)")
		help       = flag.Bool("help", false, "Show help message")
		version    = flag.Bool("version", false, "Show version")
	)
	
	flag.Parse()
	
	if *help {
		fmt.Println("Network Monitor - Real-time network monitoring tool")
		fmt.Println("\nUsage:")
		fmt.Println("  netmon [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -ebpf      Enable eBPF-based network monitoring (requires root)")
		fmt.Println("  -help      Show this help message")
		fmt.Println("  -version   Show version")
		fmt.Println("\nKeyboard shortcuts:")
		fmt.Println("  p          Switch to process detail view")
		fmt.Println("  q/ESC      Quit (or return to main view from process view)")
		fmt.Println("  /          Filter processes (in process view)")
		os.Exit(0)
	}
	
	if *version {
		fmt.Println("Network Monitor v1.0.0")
		os.Exit(0)
	}
	
	// Initialize eBPF collector if enabled
	var ebpfCollector *collector.EBPFCollector
	if *enableEBPF {
		ec, err := collector.NewEBPFCollector()
		if err != nil {
			log.Printf("Warning: Failed to initialize eBPF collector: %v", err)
			log.Printf("Continuing without eBPF support...")
		} else {
			ec.SetEnabled(true)
			if err := ec.Start(); err != nil {
				log.Printf("Warning: Failed to start eBPF collector: %v", err)
				log.Printf("Continuing without eBPF support...")
				if err.Error() == "eBPF is only supported on Linux" {
					log.Printf("Note: eBPF features require Linux operating system")
				}
			} else {
				ebpfCollector = ec
				defer ebpfCollector.Stop()
				log.Println("eBPF-based monitoring enabled")
			}
		}
	}
	
	dashboard := ui.NewDashboard()
	
	// Pass eBPF collector to dashboard if available
	if ebpfCollector != nil {
		dashboard.SetEBPFCollector(ebpfCollector)
	}
	
	if err := dashboard.Run(); err != nil {
		log.Fatal(err)
	}
}