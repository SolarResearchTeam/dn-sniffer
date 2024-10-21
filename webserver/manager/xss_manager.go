package manager

import (
	"context"
	"net/http"
	"time"
	"sync"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	ssl "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/ssl"
)

type XSSServer struct {
	Config          *config.Config
	Server *http.Server
}

func NewXSSServer(config *config.Config) *XSSServer {
	xsshunterserver := &http.Server{
		ReadTimeout: 10 * time.Second,
		Addr:        config.XSSHunter.XSSHunterURL,
		ErrorLog: 	 log.NoopLogger,
	}

	ws := &XSSServer{
		Config:          config,
		Server: xsshunterserver,
	}
	ws.RegisterRoutes()
	return ws
}

func (ws *XSSServer) Start(wg *sync.WaitGroup) {
	var err error
	defer wg.Done()
	if ws.Config.XSSHunter.UseTLS {
		err = ssl.ListenAndServeTLS(ws.Server)
	} else {
		err = ws.Server.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		log.Console_Info("XSSServer(Graceful stop)")
	} else if err != nil {
			log.Fatal("XSSServer(Start)",err.Error())
	}
}
func (ws *XSSServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return ws.Server.Shutdown(ctx)
}

func (ws *XSSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws.Server.Handler.ServeHTTP(w, r)
}