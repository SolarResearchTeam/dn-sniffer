package interact

import (
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/interact/sources/smtpd"
)

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	Id   string
	Chan chan bool
	Port int

	smtpServer smtpd.Server
}

// NewSMTPServer returns a new TLS & Non-TLS SMTP server.
func NewSMTPServer(id string, port int, channel chan bool) *SMTPServer {
	server := &SMTPServer{Id: id, Port: port, Chan: channel}

	server.smtpServer = smtpd.Server{
		Addr:        fmt.Sprintf("%s:%d", config.Conf.Interact.ListenIP, port),
		AuthHandler: server.authHandler,
		HandlerRcpt: server.rcptHandler,
		Hostname:    "",
		Appname:     "smtp",
		Handler:     server.defaultHandler,
	}
	return server
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(secure bool) {
	defer cleanup_chans(h.Id)

	set_running(h.Id)

	go h.RoutinWorker(secure)

	<-h.Chan

	ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
	h.smtpServer.Shutdown(ctx)
	log.Info("InteractSHSMTP(ListenAndServe)", fmt.Sprintf("Server smtp %s stopped", h.Id))
}

func (h *SMTPServer) RoutinWorker(secure bool) {
	defer Recover(h.Id,"InteractSHSMTP(RoutinWorker)")
	if secure {
		h.smtpServer.ConfigureTLS(config.Conf.SSL.Path + "/default/cert.pem", config.Conf.SSL.Path + "/default/key.pem")
	}
	if err := h.smtpServer.ListenAndServe(); err != smtpd.ErrServerClosed {
		write_err(h.Id,"InteractSHSMTP(RoutinWorker)",err.Error())
		h.Chan <- true
	}
}

func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {

	dataString := string(data)
	content := fmt.Sprintf("SMTP send request:\n From: %s\n To: %s\n Data: %s\n", from, to, dataString)
	host := remoteAddr.String()

	recordInteraction(h.Id, host, content)
	return nil
}

func (h *SMTPServer) authHandler(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {

	uname := string(username)
	upass := string(password)
	content := fmt.Sprintf("SMTP login request:\n Type: %s\n Username: %s\n Password: %s\n", mechanism, uname, upass)
	host := remoteAddr.String()

	recordInteraction(h.Id, host, content)
	return true, nil
}

func (h *SMTPServer) rcptHandler(remoteAddr net.Addr, from string, to string) bool {
	content := fmt.Sprintf("SMTP RCPT request:\n From: %s\n To: %s\n", from, to)
	host := remoteAddr.String()

	recordInteraction(h.Id, host, content)
	return true
}