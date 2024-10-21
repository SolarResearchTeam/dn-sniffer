package controllers

import (
	"net/http"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"
	"strings"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
)


func CertNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "cert_new").ExecuteTemplate(w, "base", Default_context{User:user})
}

func CertsInfo(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)

	type Cert struct {
		Name string
		Issuer string 
		Renewer bool
		DNSNames []string
		NotAfter time.Time
		NotBefore time.Time
	}

	type Context struct {
		Certs []Cert
		User *ds.Users
	}

	page_context := Context{User: user}
	certs := []Cert{}
	path := config.Conf.SSL.Path
	entries, err := os.ReadDir(path)
	if err != nil {
		log.Error("Webserver(CertsInfo)", err.Error())
		http.Redirect(w, r, "/logs", 301)
		return
	} else {
		for _,entrie := range entries {
			if !entrie.IsDir() {
				continue
			}
			c := Cert{}
			c.Name = entrie.Name()

			c.Renewer,_ = models.Database.GetRenewer(c.Name)

			cert_bytes, err := os.ReadFile(path + "/" + entrie.Name() +"/cert.pem")
			if err == nil {
				 block, _ := pem.Decode(cert_bytes)
				 if block == nil {
				 	c.Issuer = "Cert decode error"
				 	log.Error("Webserver(CertsInfo)", "Cert decode error")
				 } else {
					cert,err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						c.Issuer = strings.Join(cert.Issuer.Organization, " ") +", CN("+cert.Issuer.CommonName+")"
						c.DNSNames = cert.DNSNames
						c.NotAfter = cert.NotAfter
						c.NotBefore = cert.NotBefore
					} else {
						c.Issuer = "Cert parse error: " +err.Error()
						log.Error("Webserver(CertsInfo)", err.Error())
					}
				}
			} else {
				c.Issuer = "Cert read error: " +err.Error()
				log.Error("Webserver(CertsInfo)", err.Error())
			}
			certs = append(certs,c)
		}
	}
	page_context.Certs = certs
	utils.GetTemplate(w, r, "certs").ExecuteTemplate(w, "base", page_context)
}