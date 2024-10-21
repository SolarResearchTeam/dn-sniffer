package interact

import (
	"fmt"
	"time"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

//Panic resolver
func Recover(id, source string) {
	var panic_err string
    if r := recover(); r != nil {
        // find out exactly what the error was and set err
        switch x := r.(type) {
        case string:
        	panic_err = x
        case error:
        	panic_err = x.Error()
        default:
        	panic_err = "unknown panic"
        }

		write_err(id,source,panic_err)

	    HardStopServer(id)
    }
}


//Set interract status
func set_running(id string) {
	server, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("IntercatSHManager(StartServer)", err.Error())
		return
	}
	server.Running = true
	server.Errors = ""
	_, err = models.Database.EditInteract(server)
	if err != nil {
		log.Error("IntercatSHManager(StartServer)", err.Error())
		return
	}
}

//Logger for panics and other errors
func write_err(id,source,err string) {
	log.Error(source, fmt.Sprintf("Server %s: %s",id,err))
	server, err_d := models.Database.GetInteractById(id)
	if err_d != nil {
		log.Error(source, err_d.Error())
		return
	}
	server.Running = false
	server.Errors = err
	_, err_d = models.Database.EditInteract(server)
	if err_d != nil {
		log.Error(source, err_d.Error())
		return
	}
}

//Cleanup if anything left
func cleanup_chans(id string) {
	if _, ok := Channels[id]; ok {
		close(Channels[id])
		delete(Channels, id)
	}
}

//Universal hit writer
func recordInteraction(id,host,content string) {
	time_now := time.Now().Format("2006.01.02 15:04:01")
	ih := ds.Interact_hit{ServerId: id, ClientAddr: host, Content: content, Time: time_now}
	models.Database.AddInteractHit(&ih)
}
