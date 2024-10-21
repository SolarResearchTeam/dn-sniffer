package smtpsender

import (
	"github.com/SolarResearchTeam/dn-sniffer/config"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"crypto/tls"
	"net/smtp"
	"strconv"
	"strings"
)

type SMTPSenderType struct {
	Client        *smtp.Client
	From          string
	ServerAddress string
	ServerPort    string
	Auth          smtp.Auth
	TLSConfig     *tls.Config
	URL           string
}

var RestorePassword string = "From: %s\r\n" +
	"To: %s\r\n" +
	"Subject: Password restoration\r\n\r\n" +
	"Your password restore link: %s\r\n"

var SMTPSender SMTPSenderType

func NewSMTPSender(config *config.Config) *SMTPSenderType {
	strconv.Itoa(config.SMTP.ServerPort)

	SMTPSender = SMTPSenderType{
		From:          config.SMTP.From,
		ServerAddress: config.SMTP.ServerAddress,
		ServerPort:    strconv.Itoa(config.SMTP.ServerPort),
	}
	hostname := ""
	if config.WebServerConf.Hostname != "" {
		hostname = config.WebServerConf.Hostname + ":" + strings.Split(config.WebServerConf.WebServerURL, ":")[1]
	} else {
		hostname = config.WebServerConf.WebServerURL
	}
	if config.WebServerConf.UseTLS {
		SMTPSender.URL = "https://" + hostname + "/restore/"
	} else {
		SMTPSender.URL = "http://" + config.WebServerConf.Hostname + ":" + strings.Split(config.WebServerConf.WebServerURL, ":")[1] + "/restore/"
	}
	if config.SMTP.User == "" {
		SMTPSender.Auth = nil
	} else {
		SMTPSender.Auth = smtp.PlainAuth("", config.SMTP.User, config.SMTP.Password, config.SMTP.ServerAddress)

	}
	if config.SMTP.TLS {
		SMTPSender.TLSConfig = &tls.Config{
			InsecureSkipVerify: config.SMTP.VerifyTLS,
			ServerName:         config.SMTP.ServerAddress,
		}
	} else {
		SMTPSender.TLSConfig = nil
	}
	return &SMTPSender
}

func (sender *SMTPSenderType) Dial() bool {
	var err error
	sender.Client, err = smtp.Dial(sender.ServerAddress + ":" + sender.ServerPort)
	if err != nil {
		log.Error("SMTPSender(Dial)", err.Error())
		return false
	}
	return true
}

func (sender *SMTPSenderType) SendMessage(to string, message string) {
	if sender.Dial() {
		defer sender.Client.Quit()
		if sender.TLSConfig != nil {
			sender.Client.StartTLS(sender.TLSConfig)
		}
		if sender.Auth != nil {
			err := sender.Client.Auth(sender.Auth)
			if err != nil {
				log.Error("SMTPSender(SendMessage)", err.Error())
				return
			}
		}
		err := sender.Client.Mail(sender.From)
		if err != nil {
			log.Error("SMTPSender(SendMessage)", err.Error())
			return
		}
		err = sender.Client.Rcpt(to)
		if err != nil {
			log.Error("SMTPSender(SendMessage)", err.Error())
			return
		}
		w, err := sender.Client.Data()
		if err != nil {
			log.Error("SMTPSender(SendMessage)", err.Error())
			return
		}
		_, err = w.Write([]byte(message))
		if err != nil {
			log.Error("SMTPSender(SendMessage)", err.Error())
			return
		}
		err = w.Close()
		if err != nil {
			log.Error("SMTPSender(SendMessage)", err.Error())
			return
		}
	}
}
