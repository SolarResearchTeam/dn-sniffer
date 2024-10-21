package controllers

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	mngr "github.com/SolarResearchTeam/dn-sniffer/webserver/interact"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
)

func UpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Config *config.Config
		User *ds.Users
	}
	if r.Method == "GET" {
		utils.GetTemplate(w, r, "updateconfig").ExecuteTemplate(w, "base",Context{Config: &config.Conf,User:user})
		return
	}
	if r.Method == "POST" {
		type request struct {
			TTL 	string `json:"ttl"`
			IP 		string `json:"answerip"`
			Zones 	string `json:"primary_zone"`
		}

		var req request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Error("DNSServer(UpdateDNSConfig)", err.Error())
			http.Redirect(w, r, "/logs", 301)
			return
		}


		if req.TTL != "" {
			ttl, err := strconv.Atoi(req.TTL)
			if err == nil && ttl > -1 && ttl < 4294967296{
				config.Conf.DNS.TTL = ttl
			}
		}

		if req.IP != "" {
			if net.ParseIP(req.IP) != nil {
				config.Conf.DNS.AnswerIP = req.IP
			}
		}

		//I WANT TO RYDE MY BICYCLE
		if strings.Split(req.Zones,",")[0] != "" {
			zones := []string{}
			for _,zone := range(strings.Split(req.Zones,",")) {
				if zone != "" {
					zones = append(zones,zone)
				}
			}
			config.Conf.DNS.PrimaryZone = zones
		}

		SaveConfig(&config.Conf)
		http.Redirect(w, r, "/zones", 301)
		return
	}
}

func UpdateInteractConfig(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Config *config.Config
		User *ds.Users
	}
	if r.Method == "GET" {
		utils.GetTemplate(w, r, "updateinteractconfig").ExecuteTemplate(w, "base", Context{Config: &config.Conf,User:user})
		return
	}
	if r.Method == "POST" {
		type request struct {
			IP 		string `json:"listenip"`
		}

		var req request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Error("DNSServer(UpdateInteractConfig)", err.Error())
			http.Redirect(w, r, "/logs", 301)
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
				http.Redirect(w, r, "/interact", 301)
				return
			}
			for _, server := range *servers {
				if server.Running {
					mngr.RestartServer(server.Id.Hex())
				}
			}
			//
			SaveConfig(&config.Conf)
		}
	}
	http.Redirect(w, r, "/interacts", 301)
}

func SaveConfig(config *config.Config) {
	file, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		log.Error("DNSServer(UpdateDNSConfig)", err.Error())
		return
	}
	err = ioutil.WriteFile("./config.json", file, 0644)
	if err != nil {
		log.Error("DNSServer(UpdateDNSConfig)", err.Error())
		return
	}
}
