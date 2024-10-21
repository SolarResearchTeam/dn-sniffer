package main

import (
	"os"
	"os/signal"
	"syscall"
	"sync"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"

	"github.com/SolarResearchTeam/dn-sniffer/config"

	web_manager "github.com/SolarResearchTeam/dn-sniffer/webserver/manager"
	dns_manager "github.com/SolarResearchTeam/dn-sniffer/dnsserver"

	"github.com/alecthomas/kingpin/v2"
)

var (
	configPath = kingpin.Flag("config", "Location of config.json.").Default("./config.json").String()
)

func main() {
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Parse()
	_, err := config.LoadConfig(*configPath)
	if err != nil {
		kingpin.CommandLine.FatalUsage("Unable to parse configuration file: %s\n",*configPath)
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go web_manager.Start(&wg)
	go dns_manager.Start(&wg)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Info("Main", "Recieved Interrupt. Trying to shutdown everything gracefully...")
	web_manager.Shutdown()
	dns_manager.Shutdown()
	wg.Wait()
}
