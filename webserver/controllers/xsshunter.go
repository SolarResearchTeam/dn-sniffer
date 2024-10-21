package controllers

import (
	"net/http"
	"time"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)

func XssHunter(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Settings *[]ds.HunterSetting
		User *ds.Users
	}
	hn, err := models.Database.XssHunterAllSettings()
	if err != nil {
		utils.GetTemplate(w, r, "xsshunter").ExecuteTemplate(w, "base", Context{Settings:hn,User:user})
	}
	utils.GetTemplate(w, r, "xsshunter").ExecuteTemplate(w, "base", Context{Settings:hn,User:user})
}

func XssHunterNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Settings *config.XSSHunter
		User *ds.Users
	}
	conf := config.Conf.XSSHunter
	utils.GetTemplate(w, r, "xsshunternew").ExecuteTemplate(w, "base", Context{Settings:&conf,User:user})
}

func XssHunterNewPayloads(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Uuid string
		User *ds.Users
	}
	utils.GetTemplate(w, r, "xsshunterpayloadsnew").ExecuteTemplate(w, "base",Context{Uuid: mux.Vars(r)["uuid"],User:user})
}

func XssHunterPayloads(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Settings *ds.Hunter
		User *ds.Users
	}
	setting, err := models.Database.XssHunterGetSettingsByUuid(mux.Vars(r)["uuid"])
	if err != nil {
		log.Error("XSSHunter payload", err.Error())
	}
	hunter := &ds.Hunter{
		UUID:    mux.Vars(r)["uuid"],
		Setting: setting,
	}
	temp := utils.GenerateSamples(hunter.Setting.MotherShipUrl, hunter.Setting.Payload.Name, hunter.Setting.Name)
	hunter.Setting.Payload.Sample = temp
	utils.GetTemplate(w, r, "xsshunterpayloads").ExecuteTemplate(w, "base", Context{Settings:hunter,User:user})
}

func XssHunterHits(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Settings *ds.Hunter
		User *ds.Users
	}

	hits, err := models.Database.XssHunterGetAllHitsByUUID(mux.Vars(r)["uuid"])
	hunter := &ds.Hunter{
		UUID: mux.Vars(r)["uuid"],
	}
	if err != nil {
		hunter.Hits = nil
	}
	hunter.Hits = hits

	utils.GetTemplate(w, r, "xsshits").ExecuteTemplate(w, "base", Context{Settings:hunter,User:user})
}

func XssHunterSettings(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Settings *ds.HunterSetting
		User *ds.Users
	}
	settings, err := models.Database.XssHunterGetSettingsByUuid(mux.Vars(r)["uuid"])
	if settings.Id.IsZero() || err != nil {
		utils.GetTemplate(w, r, "xsshuntersettings").ExecuteTemplate(w, "base", Context{Settings:settings,User:user})
	}
	utils.GetTemplate(w, r, "xsshuntersettings").ExecuteTemplate(w, "base", Context{Settings:settings,User:user})
}

func XssHunterServePayload(w http.ResponseWriter, r *http.Request) {
	hunter, err := models.Database.XssHunterByName(mux.Vars(r)["name"])
	if err != nil {
		log.Error("XSSHunter Server Payload", err.Error())
	}
	if r.Method == "GET" {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(hunter.Payload.Payload))
	}
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "xtoken")
	}
	if r.Method == "POST" {
		if r.FormValue("injection_key") == hunter.UUID {
			hit := ds.HunterHit{}
			hit.HunterUUID = hunter.UUID
			hit.Time = time.Now().Format("2006.01.02 15:04")
			if r.Header.Get("X-Real-Ip") != "" {
				hit.IP = r.Header.Get("X-Real-Ip")
			} else {
				hit.IP = r.RemoteAddr
			}
			hit.Screen = r.FormValue("screenshot")
			hit.Uri = r.FormValue("uri")
			hit.PageHTML = r.FormValue("dom")
			hit.Cookies = r.FormValue("cookies")
			hit.UserAgent = r.FormValue("user-agent")
			hit.BrowserTime = r.FormValue("browser-time")
			hit.Origin = r.FormValue("origin")
			models.Database.XssHunterAddHit(&hit)
		}
		w.Header().Add("Access-Control-Allow-Origin", "*")
	}
}
