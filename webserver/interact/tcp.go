package interact

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
)

// FTPServer is a ftp server instance
type TCPServer struct {
	Id   string
	Chan chan bool
	Port int

	server net.Listener
}

func NewTCPServer(id string, port int, channel chan bool) *TCPServer {
	server := &TCPServer{Id: id, Port: port, Chan: channel}
	return server
}

func (h *TCPServer) ListenAndServe(secure bool) {
	defer cleanup_chans(h.Id)

	set_running(h.Id)

	go h.RoutinWorker(secure)

	<-h.Chan
	if h.server != nil {
		h.server.Close()
	}
	log.Info("InteractSHTCP(ListenAndServe)", fmt.Sprintf("Server %s stopped", h.Id))
}

func (h *TCPServer) RoutinWorker(secure bool) {
	defer Recover(h.Id,"InteractSHTCP(RoutinWorker)")
	var err error
	if secure {
		cert, _ := tls.LoadX509KeyPair(config.Conf.SSL.Path + "/default/cert.pem", config.Conf.SSL.Path + "/default/key.pem")
		tlsconfig := tls.Config{Certificates: []tls.Certificate{cert}}
		h.server, err = tls.Listen("tcp4", fmt.Sprintf("%s:%d", config.Conf.Interact.ListenIP, h.Port), &tlsconfig)
	} else {
		h.server, err = net.Listen("tcp4", fmt.Sprintf("%s:%d", config.Conf.Interact.ListenIP, h.Port))
	}

	if err != nil {
		write_err(h.Id,"InteractSHTCP(RoutinWorker)",err.Error())
		h.Chan <- true
		return
	}

	for {
		c, err := h.server.Accept()
		if err != nil {
			continue
		}
		go h.handleConnection(c)
	}
}

func (h *TCPServer) handleConnection(c net.Conn) {
	defer func() {
		c.Close()
		Recover(h.Id,"InteractSHTCP(handleConnection)")
	}()
	data := make([]byte, 0)
	buf := make([]byte, 512)
	for i := 0; i < 5; i++ {
		len, err := c.Read(buf)
		if err != nil {
			break
		}
		data = append(data, buf[:len]...)
	}
	recordInteraction(h.Id, c.RemoteAddr().String(), string(data))
}