package main

import (
	"log"

	"github.com/nozo-moto/network-monitor/internal/ui"
)

func main() {
	dashboard := ui.NewDashboard()
	
	if err := dashboard.Run(); err != nil {
		log.Fatal(err)
	}
}