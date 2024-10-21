package dnsserver

import (
	"sync"
)

var Shutdown_chan chan interface{}

func init() {
	Shutdown_chan = make(chan interface{})
}

func Start(wg *sync.WaitGroup) {
	dns := NewDnsServer()
	go dns.Start()
	<-Shutdown_chan
	dns.Stop()
	wg.Done()
}

func Shutdown() {
	close(Shutdown_chan)
}