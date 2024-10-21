package api

import (
	"net"
	"net/http"
	"encoding/json"
	"strconv"
	"io/ioutil"

	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	mngr "github.com/SolarResearchTeam/dn-sniffer/webserver/interact"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
)

//Read
func Read_config(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type response struct {
		Config config.Config 		`json:"config"`
	}

	json.NewEncoder(w).Encode(response{Config:config.Conf,})
}

//Update DNS conf
func Update_config_dns(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		TTL 	string `json:"ttl"`
		IP 		string `json:"answerip"`
		Zones 	[]string `json:"primary_zone"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Error("API(UpdateDNSConfig)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	if req.TTL != "" {
		ttl, err := strconv.Atoi(req.TTL)
		if err == nil && ttl > -1 && ttl < 4294967296{
			json.NewEncoder(w).Encode(Response{Err:"Bad TTL. 0 <= TTL < 4294967296",})
			return
		} else if err != nil {
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
	}

	if req.IP != "" {
		if net.ParseIP(req.IP) != nil {
			config.Conf.DNS.AnswerIP = req.IP
		} else {
			json.NewEncoder(w).Encode(Response{Err:"Bad IP addr",})
			return
		}
	}

	if len(req.Zones) > 0 {
		config.Conf.DNS.PrimaryZone = req.Zones
	} else {
		json.NewEncoder(w).Encode(Response{Err:"Empty zones",})
		return
	}

	err = saveConfig(&config.Conf)
	if err != nil {
		log.Error("API(UpdateDNSConfig)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
}

//Update interact conf
func Update_config_interact(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		IP 		string `json:"listenip"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Error("API(UpdateInteractConfig)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	if req.IP != "" {
		if net.ParseIP(req.IP) != nil {
			config.Conf.Interact.ListenIP = req.IP
		}
		//restart intercats
		servers, err := models.Database.GetAllInteract()
		if err != nil {
			log.Error("Update Interact config", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
		for _, server := range *servers {
			if server.Running {
				mngr.RestartServer(server.Id.Hex())
			}
		}
		err = saveConfig(&config.Conf)
		if err != nil {
			log.Error("DNSServer(UpdateDNSConfig)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error(),})
			return
		}
	}
}


func saveConfig(config *config.Config) error {
	file, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("./config.json", file, 0644)
	if err != nil {
		return err
	}
	return nil
}