package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	daemon := flag.Bool("daemon", false, "Run as daemon")
	ctl := flag.Bool("ctl", false, "Run as control tool")
	flag.Parse()

	if *ctl {
		runCtl()
	} else if *daemon {
		runDaemon()
	} else {
		fmt.Println("Usage: mkbox [-daemon|-ctl]")
		os.Exit(1)
	}
}

func runDaemon() {
	app := NewApp()
	app.Run()
}

func runCtl() {
	ctl := NewCtl()
	ctl.Run()
}
