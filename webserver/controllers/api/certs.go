package api

import (
	"net/http"
	"os"
	"io"
	"encoding/json"
	"crypto/x509"
	"encoding/pem"
	"time"
	"strings"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	ssl "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/ssl"

	"github.com/gorilla/mux"
)

//Create
func Create_SSL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	name := r.FormValue("name")
	renew := r.FormValue("renew")
	generate := r.FormValue("generate")

	if generate == "yaaaas" {
		err := ssl.Gencert(name)
		if err != nil {
			log.Error("API(NewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
		if renew != "" {
			_,err = models.Database.AddRenewer(name)
			if err != nil {
				log.Error("API(NewSSL)", err.Error())
				json.NewEncoder(w).Encode(Response{Err:err.Error(),})
				return
			}
		}
json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
		return
	}
	err := os.MkdirAll(config.Conf.SSL.Path+"/"+name, os.ModePerm)
	if err != nil {
		log.Error("API(NewSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	err = r.ParseMultipartForm(32 << 20)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Error("API(NewSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	mForm := r.MultipartForm
	for k, _ := range mForm.File {
		file, _, err := r.FormFile(k)
		if err != nil {
			log.Error("API(NewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
		defer file.Close()
		localFileName := config.Conf.SSL.Path + "/" + name + "/" + k + ".pem"
		out, err := os.OpenFile(localFileName, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Error("API(NewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
		defer out.Close()
		_, err = io.Copy(out, file)
		if err != nil {
			log.Error("API(NewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
	}

	err = ssl.ReloadCerts()
	if err != nil {
		log.Error("API(NewSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	if renew != "" {
		_,err := models.Database.AddRenewer(name)
		if err != nil {
			log.Error("API(NewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
	}


json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
}

//Read
func Read_SSLs(w http.ResponseWriter, r *http.Request) {
	type Cert struct {
		Name string
		Issuer string 
		Renewer bool
		DNSNames []string
		NotAfter time.Time
		NotBefore time.Time
	}

	type response struct {
		Error string 		`json:"error"`
		Certs []Cert 		`json:"certs"`
	}

	certs := []Cert{}
	path := config.Conf.SSL.Path
	entries, err := os.ReadDir(path)
	if err != nil {
		log.Error("Webserver(CertsInfo)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
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
	json.NewEncoder(w).Encode(response{Certs:certs})
}

//Renew
func Renew_SSL(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	err := ssl.Gencert(name)
	if err != nil {
		log.Error("API(RenewSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	} 
json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
}

//Reload
func Reload_SSL(w http.ResponseWriter, r *http.Request) {
	err := ssl.ReloadCerts()
	if err != nil {
		log.Error("API(ReloadSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	} 
json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
}

//Set renew for cert
func SetRenew_SSL(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	action := mux.Vars(r)["action"]

	if action == "set" {
		_,err := models.Database.AddRenewer(name)
		if err != nil {
			log.Error("API(SetRenewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
	} else if action == "unset" {
		_, err := models.Database.DelRenewer(name)
		if err != nil {
			log.Error("API(SetRenewSSL)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		} 
	}
json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
}

//Delete
func Delete_SSL(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	err := os.RemoveAll(config.Conf.SSL.Path + "/" + name)
	if err != nil {
		log.Error("API(DelSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	} 

	_, err = models.Database.DelRenewer(name)
	if err != nil {
		log.Error("API(DelSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	} 

	err = ssl.ReloadCerts()
	if err != nil {
		log.Error("API(DelSSL)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

json.NewEncoder(w).Encode(Response{Redirect:"/certs",})
}