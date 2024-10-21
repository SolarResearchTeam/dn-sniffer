package manager

import (
	"context"
	"net/http"
	"time"
	"sync"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	mngr "github.com/SolarResearchTeam/dn-sniffer/webserver/interact"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	ssl "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/ssl"
)


type WebServer struct {
	Server          *http.Server
	Config          *config.Config
}

func NewWebServer(config *config.Config) *WebServer {
	defaultServer := &http.Server{
		ReadTimeout: 10 * time.Second,
		Addr:        config.WebServerConf.WebServerURL,
		ErrorLog: 	 log.NoopLogger,
	}

	ws := &WebServer{
		Server:          defaultServer,
		Config:          config,
	}

	ws.RegisterRoutes()
	return ws
}

func NewWebServer_Multiplex(config *config.Config) *WebServer {
	defaultServer := &http.Server{
		ReadTimeout: 10 * time.Second,
		Addr:        config.WebServerConf.WebServerURL,
		ErrorLog: 	 log.NoopLogger,
	}

	ws := &WebServer{
		Server:          defaultServer,
		Config:          config,
	}

	ws.RegisterMultiplexor()
	return ws
}

func (ws *WebServer) Start(wg *sync.WaitGroup) {
	var err error
	defer wg.Done()
	if ws.Config.WebServerConf.UseTLS {
		err = ssl.ListenAndServeTLS(ws.Server)
	} else {
		err = ws.Server.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		log.Console_Info("Webserver(Graceful stop)")
	} else if err != nil {
		log.Fatal("Webserver(Start)",err.Error())
	}
}

func (ws *WebServer) AutostartInteract() {
	interactservers, err := models.Database.GetAllInteract()
	if err != nil {
		log.Error("Webserver(AutostartInteract)", err.Error())
		return
	}
	for _, server := range *interactservers {
		if server.Running {
			mngr.StartServer(server.Id.Hex())
		}
	}
}

func (ws *WebServer) AutostopInteract(wg *sync.WaitGroup) {
	defer wg.Done()
	interactservers, err := models.Database.GetAllInteract()
	if err != nil {
		log.Error("Webserver(AutostopInteract)", err.Error())
		return
	}
	for _, server := range *interactservers {
		if server.Running {
			mngr.HardStopServer(server.Id.Hex())
		}
	}
	//Wait for stop
	time.Sleep(5*time.Second)
}

func (ws *WebServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return ws.Server.Shutdown(ctx)
}

func (ws *WebServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws.Server.Handler.ServeHTTP(w, r)
}