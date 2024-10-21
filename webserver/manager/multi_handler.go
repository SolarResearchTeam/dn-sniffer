package manager

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	logger "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

func (ws *WebServer) RegisterMultiplexor() {
	ws.Server.Handler = NewMultiplexor()
}

func (ws *WebServer) RegisterRoutes() {
	ws.Server.Handler = NewAdminMultiplexor()
}

func (ws *XSSServer) RegisterRoutes() {
	ws.Server.Handler = NewXSSMultiplexor()
}

func NewMultiplexor() http.HandlerFunc {
	admin_handler := new_admin_handler()
	xss_handler := new_xss_handler()
	return func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.Split(r.Host, ":")[0]
		//Route for admin
		if hostname == config.Conf.WebServerConf.Hostname {
			admin_handler(w, r)
			return
		}

		//Route for XSS hunter
		is_hunter, _ := models.Database.XssHunterGetByDomain(hostname)
		if is_hunter {
			xss_handler(w, r)
			return
		}

		//Route for interact
		host, port, _ := net.SplitHostPort(config.Conf.WebServerConf.WebServerURL)
		port_i, _ := strconv.Atoi(port)
		if host == config.Conf.Interact.ListenIP {
			interact, _ := models.Database.GetIneractOnAdminPort(port_i)
			if !interact.Id.IsZero() {
				interact_handler(w, r, interact.Id.Hex(), interact.Sharing)
				return
			}
		}
		utils.GetTemplate(w, r, "403").ExecuteTemplate(w, "base", nil)
		return
	}
}

func NewAdminMultiplexor() http.HandlerFunc {
	admin_handler := new_admin_handler()
	return func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.Split(r.Host, ":")[0]
		//Route for admin
		if hostname == config.Conf.WebServerConf.Hostname {
			admin_handler(w, r)
			return
		}

		//Route for interact
		base_host, base_port, _ := net.SplitHostPort(config.Conf.WebServerConf.WebServerURL)
		port_i, _ := strconv.Atoi(base_port)
		if base_host == config.Conf.Interact.ListenIP {
			interact, _ := models.Database.GetIneractOnAdminPort(port_i)
			if !interact.Id.IsZero() {
				interact_handler(w, r, interact.Id.Hex(), interact.Sharing)
				return
			}
		}
		utils.GetTemplate(w, r, "403").ExecuteTemplate(w, "base", nil)
		return
	}
}

func NewXSSMultiplexor() http.HandlerFunc {
	xss_handler := new_xss_handler()
	return func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.Split(r.Host, ":")[0]

		//Route for XSS hunter
		is_hunter, _ := models.Database.XssHunterGetByDomain(hostname)
		if is_hunter {
			xss_handler(w, r)
			return
		}

		//Route for interact
		host, port, _ := net.SplitHostPort(config.Conf.XSSHunter.XSSHunterURL)
		port_i, _ := strconv.Atoi(port)
		if host == config.Conf.Interact.ListenIP {
			interact, _ := models.Database.GetIneractOnAdminPort(port_i)
			if !interact.Id.IsZero() {
				interact_handler(w, r, interact.Id.Hex(), interact.Sharing)
				return
			}
		}
		utils.GetTemplate(w, r, "403").ExecuteTemplate(w, "base", nil)
		return
	}
}

func interact_handler(w http.ResponseWriter, req *http.Request, id string, sharing bool) {
	domain := req.Host
	w.Header().Set("Server", domain)

	if stringsutil.HasPrefixI(req.URL.Path, fmt.Sprintf("/%s/", id)) && sharing {
		abs := config.Conf.Interact.TmpDir
		os.Mkdir(abs, os.ModePerm)
		http.StripPrefix(fmt.Sprintf("/%s/", id), disableDirectoryListing(http.FileServer(http.Dir(abs)))).ServeHTTP(w, req)
	} else if req.URL.Path == "/" {
		fmt.Fprintf(w, "%s", domain)
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

	//1Mb Limit
	req.Body = http.MaxBytesReader(w, req.Body, 1048576)
	var reqString = ""
	r, err := httputil.DumpRequest(req, true)
	if err != nil && err != io.EOF {
		r, err = httputil.DumpRequest(req, false)
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
	time_now := time.Now().Format("2006.01.02 15:04:01")
	ih := ds.Interact_hit{ServerId: id, ClientAddr: host, Content: reqString, Time: time_now}
	_, err = models.Database.AddInteractHit(&ih)
	if err != nil {
		logger.Error("InteractHTTP(handleInteraction)", err.Error())
	}
}

func disableDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
