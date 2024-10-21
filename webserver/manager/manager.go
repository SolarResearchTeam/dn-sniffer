package manager

import (
	"sync"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	smtpsender "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/smtpsender"
	ssl "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/ssl"
)

var Shutdown_chan chan interface{}

func init() {
	Shutdown_chan = make(chan interface{})
}

func Start(wg *sync.WaitGroup) {
	int_wg := sync.WaitGroup{}

//Init sub modules
	//Init smtp sender (for password restore function)
	smtpsender.NewSMTPSender(&config.Conf)

	//Init mongo connection
	err := models.NewDao(&config.Conf)
	if err != nil {
		log.Console_Fatalf("%s: %s","Database Connect",err.Error())
	}

	//Init DB if its empty
	err = models.Database.Init()
	if err != nil {
		log.Console_Fatalf("%s: %s","Database Init",err.Error())
	}

	//Init session storage
	mid.SessionStoreInit()

	//Init TLS config (load certs / gen certs if not any)
	err = ssl.NewTlsConfig()
	if err != nil {
		log.Console_Fatalf("%s: %s","TLS Init",err.Error())
	}


//Create multihandler server
	if config.Conf.WebServerConf.WebServerURL == config.Conf.XSSHunter.XSSHunterURL {
		webserver := NewWebServer_Multiplex(&config.Conf)

		int_wg.Add(2)
		go webserver.Start(&int_wg)
		webserver.AutostartInteract()

		<-Shutdown_chan
		webserver.AutostopInteract(&int_wg)
		webserver.Shutdown()
		int_wg.Wait()

		wg.Done()

//Create regular servers
	} else {
		webserver := NewWebServer(&config.Conf)
		xssserver := NewXSSServer(&config.Conf)

		int_wg.Add(3)
		go webserver.Start(&int_wg)
		go xssserver.Start(&int_wg)
		go ssl.Renewer()
		webserver.AutostartInteract()

		<-Shutdown_chan
		webserver.AutostopInteract(&int_wg)
		webserver.Shutdown()
		xssserver.Shutdown()
		int_wg.Wait()

		wg.Done()
	}
}

func Shutdown() {
	close(Shutdown_chan)
}