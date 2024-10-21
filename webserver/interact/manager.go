package interact

import (
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

var Channels map[string](chan bool)

func init() {
	Channels = make(map[string](chan bool))
}

func StartServer(id string) {
	server, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("IntercatSHManager(StartServer)", err.Error())
		return
	}

	Channels[id] = make(chan bool)
	
	switch srv_type := server.Type; srv_type {
	case "ldap":
		go NewLDAPServer(id, server.ListenPort, Channels[id]).ListenAndServe()
	case "http":
		go NewHTTPServer(id, server.ListenPort, Channels[id], server.Sharing).ListenAndServe(false)
	case "https":
		go NewHTTPServer(id, server.ListenPort, Channels[id], server.Sharing).ListenAndServe(true)
	case "smtp":
		go NewSMTPServer(id, server.ListenPort, Channels[id]).ListenAndServe(false)
	case "smtps":
		go NewSMTPServer(id, server.ListenPort, Channels[id]).ListenAndServe(true)
	case "ftp":
		go NewFTPServer(id, server.ListenPort, Channels[id], server.Sharing).ListenAndServe(false)
	case "ftps":
		go NewFTPServer(id, server.ListenPort, Channels[id], server.Sharing).ListenAndServe(true)
	case "tcp":
		go NewTCPServer(id, server.ListenPort, Channels[id]).ListenAndServe(false)
	case "tls":
		go NewTCPServer(id, server.ListenPort, Channels[id]).ListenAndServe(true)
	}
}

func StopServer(id string) {
	server, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("IntercatSHManager(StopServer)", err.Error())
		return
	}
	if server.Running {
		if _, ok := Channels[id]; ok {
			close(Channels[id])
			delete(Channels, id)
		}
		server.Running = false
		_, err = models.Database.EditInteract(server)
		if err != nil {
			log.Error("IntercatSHManager(StopServer)", err.Error())
		}
	}
}

//Alt stop function used on ctrl+c or panic
func HardStopServer(id string) {
	server, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("IntercatSHManager(StopServer)", err.Error())
		return
	}
	if server.Running {
		if _, ok := Channels[id]; ok {
			close(Channels[id])
			delete(Channels, id)
		}
	}
}

func DelServer(id string) {
	if _, ok := Channels[id]; ok {
		close(Channels[id])
		delete(Channels, id)
	}
	_, err := models.Database.InteractClear(id)
	if err != nil {
		log.Error("IntercatSHManager(DelServer)", err.Error())
		return
	}
	_, err = models.Database.InteractDel(id)
	if err != nil {
		log.Error("IntercatSHManager(DelServer)", err.Error())
		return
	}
}

func RestartServer(id string) {
	StopServer(id)
	StartServer(id)
}