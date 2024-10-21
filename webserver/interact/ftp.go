package interact

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"

	ftpserver "goftp.io/server/v2"
	"goftp.io/server/v2/driver/file"
)

// FTPServer is a ftp server instance
type FTPServer struct {
	Id   string
	Chan chan bool
	Port int

	ftpServer  *ftpserver.Server
	ftpsServer *ftpserver.Server
}

// NewFTPServer returns a new TLS & Non-TLS FTP server.
func NewFTPServer(id string, port int, channel chan bool, serve_files bool) *FTPServer {
	server := &FTPServer{Id: id, Port: port, Chan: channel}

	var ftpFolder string

	if serve_files {
		ftpFolder = config.Conf.Interact.TmpDir
		os.Mkdir(ftpFolder, os.ModePerm)
	} else {
		ftpFolder, _ = os.MkdirTemp("", "")
	}

	driver, _ := file.NewDriver(ftpFolder)
	nopDriver := NewNopDriver(driver)

	opt := &ftpserver.Options{
		Name:     "ftp",
		Hostname: config.Conf.Interact.ListenIP,
		Driver:   nopDriver,
		Port:     port,
		Perm:     ftpserver.NewSimplePerm(id, id),
		Logger:   server,
		Auth:     &NopAuth{},
	}

	// create ftp server
	ftpServer, _ := ftpserver.NewServer(opt)
	server.ftpServer = ftpServer
	ftpServer.RegisterNotifer(server)

	// create sftp server
	opt.TLS = true
	
	opt.CertFile = config.Conf.SSL.Path + "/default/cert.pem"
	opt.KeyFile = config.Conf.SSL.Path + "/default/key.pem"

	ftpsServer, _ := ftpserver.NewServer(opt)
	server.ftpsServer = ftpsServer
	ftpsServer.RegisterNotifer(server)

	return server
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *FTPServer) ListenAndServe(secure bool) {
	defer cleanup_chans(h.Id)

	set_running(h.Id)

	go h.RoutinWorker(secure)

	<-h.Chan
	if secure {
		h.ftpsServer.Shutdown()
	} else {
		h.ftpServer.Shutdown()
	}
	log.Info("Interact: FTPServer(ListenAndServe)", fmt.Sprintf("Server %s stopped", h.Id))
}

func (h *FTPServer) RoutinWorker(secure bool) {
	defer Recover(h.Id, "Interact: FTPServer(RoutinWorker)")
	if secure {
		if err := h.ftpsServer.ListenAndServe(); err != ftpserver.ErrServerClosed {
			write_err(h.Id,"Interact: FTPServer(RoutinWorker)",err.Error())
			h.Chan <- true
		}
	} else {
		if err := h.ftpServer.ListenAndServe(); err != ftpserver.ErrServerClosed {
			write_err(h.Id,"Interact: FTPServer(RoutinWorker)",err.Error())
			h.Chan <- true
		}
	}
}

func (h *FTPServer) Print(sessionID string, message interface{})              {}
func (h *FTPServer) Printf(sessionID string, format string, v ...interface{}) {}
func (h *FTPServer) PrintCommand(sessionID string, command string, params string) {
	h.Print(sessionID, fmt.Sprintf("%s %s", command, params))
}
func (h *FTPServer) PrintResponse(sessionID string, code int, message string) {
	h.Print(sessionID, fmt.Sprintf("%d %s", code, message))
}

func (h *FTPServer) BeforeLoginUser(ctx *ftpserver.Context, userName string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString(userName + " logging in")
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}

func (h *FTPServer) BeforePutFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("uploading " + dstPath)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting " + dstPath)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeChangeCurDir(ctx *ftpserver.Context, oldCurDir, newCurDir string) {
	//Suppress spam of cwd by ftp clients
	if oldCurDir != newCurDir {
		var b strings.Builder
		b.WriteString(ctx.Cmd)
		b.WriteString(" ")
		b.WriteString(ctx.Param)
		b.WriteString("\n")
		b.WriteString("changing directory from " + oldCurDir + " to " + newCurDir)
		recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
	}
}
func (h *FTPServer) BeforeCreateDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("creating directory " + dstPath)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting directory " + dstPath)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDownloadFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("downloading file " + dstPath)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}

func (h *FTPServer) AfterUserLogin(ctx *ftpserver.Context, userName, password string, passMatched bool, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("user " + userName + " logged in with password " + password)
	recordInteraction(h.Id, ctx.Sess.RemoteAddr().String(), b.String())
}

// Supress after actions
func (h *FTPServer) AfterFilePut(ctx *ftpserver.Context, dstPath string, size int64, err error) {
}
func (h *FTPServer) AfterFileDeleted(ctx *ftpserver.Context, dstPath string, err error) {
}
func (h *FTPServer) AfterFileDownloaded(ctx *ftpserver.Context, dstPath string, size int64, err error) {
}
func (h *FTPServer) AfterCurDirChanged(ctx *ftpserver.Context, oldCurDir, newCurDir string, err error) {
}
func (h *FTPServer) AfterDirCreated(ctx *ftpserver.Context, dstPath string, err error) {
}
func (h *FTPServer) AfterDirDeleted(ctx *ftpserver.Context, dstPath string, err error) {
}

type NopAuth struct{}

func (a *NopAuth) CheckPasswd(ctx *ftpserver.Context, name, pass string) (bool, error) {
	return true, nil
}

type NopDriver struct {
	driver ftpserver.Driver
}

func NewNopDriver(driver ftpserver.Driver) *NopDriver {
	return &NopDriver{driver: driver}
}

func (n *NopDriver) Stat(c *ftpserver.Context, s string) (os.FileInfo, error) {
	return n.driver.Stat(c, s)
}

func (n *NopDriver) ListDir(c *ftpserver.Context, s string, f func(os.FileInfo) error) error {
	return n.driver.ListDir(c, s, f)
}

func (n *NopDriver) DeleteDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) DeleteFile(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) Rename(c *ftpserver.Context, s1 string, s2 string) error {
	return nil
}

func (n *NopDriver) MakeDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) GetFile(c *ftpserver.Context, s1 string, k int64) (int64, io.ReadCloser, error) {
	return n.driver.GetFile(c, s1, k)
}

func (n *NopDriver) PutFile(c *ftpserver.Context, s string, r io.Reader, k int64) (int64, error) {
	return k, nil
}
