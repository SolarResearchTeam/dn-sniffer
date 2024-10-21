package interact

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"io"
	"strconv"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	logger "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	ssl "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/ssl"

	stringsutil "github.com/projectdiscovery/utils/strings"
)


// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	Id   string
	Chan chan bool
	Port int

	server     http.Server
	staticHandler http.Handler
}


// disableDirectoryListing disables directory listing on http.FileServer
func disableDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(id string, port int, channel chan bool, serve_files bool) *HTTPServer {
	server := &HTTPServer{Id: id, Port: port, Chan: channel}

	// If a static directory is specified, also serve it.
	if serve_files {
		abs := config.Conf.Interact.TmpDir
		os.Mkdir(abs, os.ModePerm)
		server.staticHandler = http.StripPrefix(fmt.Sprintf("/%s/", id), disableDirectoryListing(http.FileServer(http.Dir(abs))))
	}

	router := &http.ServeMux{}
	router.Handle("/", http.HandlerFunc(server.defaultHandler))

	server.server = http.Server{Addr: config.Conf.Interact.ListenIP + fmt.Sprintf(":%d", port), Handler: router, ErrorLog: logger.NoopLogger}
	return server
}

// ListenAndServe listens on http and/or https ports for the server.
func (h *HTTPServer) ListenAndServe(secure bool) {
	defer cleanup_chans(h.Id)
	host, port, _ := net.SplitHostPort(config.Conf.WebServerConf.WebServerURL)
	xss_host, xss_port, _ := net.SplitHostPort(config.Conf.XSSHunter.XSSHunterURL)
	if ((strconv.Itoa(h.Port) == port) && (host == config.Conf.Interact.ListenIP)) || ((strconv.Itoa(h.Port) == xss_port) && ( xss_host == config.Conf.Interact.ListenIP)) {
		interact, err := models.Database.GetIneractOnAdminPort(h.Port)
		if err != nil {
			write_err(h.Id,"Interact: HTTPServer(ListenAndServe)",err.Error())
			return
		} else if !interact.Id.IsZero() {
			write_err(h.Id,"Interact: HTTPServer(ListenAndServe)","Other interact already registred as multihandler")
			return
		} 
		logger.Info("Interact: HTTPServer(ListenAndServe)",fmt.Sprintf("Server %s. Register as multihandler", h.Id))
		set_running(h.Id)
	} else {
		set_running(h.Id) 
		go h.RoutinWorker(secure)

		<-h.Chan

		logger.Info("Interact: HTTPServer(ListenAndServe)", fmt.Sprintf("Server %s stopped", h.Id))
		h.server.Close()
	}
}

func (h *HTTPServer) RoutinWorker(secure bool) {
	defer Recover(h.Id,"Interact: HTTPServer(RoutinWorker)")
	if secure {
		if err := ssl.ListenAndServeTLS(&h.server); err != http.ErrServerClosed {
			write_err(h.Id,"Interact: HTTPServer(RoutinWorker)",err.Error())
			h.Chan <- true
		}
	} else {
		if err := h.server.ListenAndServe(); err != http.ErrServerClosed {
			write_err(h.Id,"Interact: HTTPServer(RoutinWorker)",err.Error())
			h.Chan <- true
		}
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	domain := req.Host
	w.Header().Set("Server", domain)

	if stringsutil.HasPrefixI(req.URL.Path, fmt.Sprintf("/%s/", h.Id)) && h.staticHandler != nil {
		h.staticHandler.ServeHTTP(w, req)
	} else if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", domain)
	} else if stringsutil.HasSuffixI(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", domain)
		w.Header().Set("Content-Type", "application/json")
	} else if stringsutil.HasSuffixI(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", domain)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", domain)
	}

	//1MB Limit 
	req.Body = http.MaxBytesReader(w, req.Body, 1*1024*1024)
	var reqString = ""
	r, err := httputil.DumpRequest(req, true)
	if err != nil && err != io.EOF {
		r, err  = httputil.DumpRequest(req, false)
		if err != nil && err != io.EOF {
			logger.Error("InteractHTTP(defaultHandler)", err.Error())
			return
		} else {
			reqString = string(r) + "<request body too large>"
		}
	} else {
		reqString = string(r)
	}

	host := req.RemoteAddr
	recordInteraction(h.Id, host, reqString)
}