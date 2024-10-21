package controllers

import (
	"net/http"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)

func BlackHoleNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "blackholenew").ExecuteTemplate(w, "base", Default_context{User:user})
}

func BlackHoleEdit(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		BlackHole *ds.BlackHole
		User *ds.Users
	}
	rb, err := models.Database.BlackHoleByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("Webserver(Blackhole)", err.Error())
		http.Redirect(w, r, "/blackhole", 301)
		return
	}
	utils.GetTemplate(w, r, "blackholeedit").ExecuteTemplate(w, "base", Context{BlackHole:rb,User:user})
}

func BlackHole(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		BlackHole *[]ds.BlackHole
		User *ds.Users
	}
	rb, err := models.Database.GetAllBlackHole()
	if err != nil {
		utils.GetTemplate(w, r, "blackhole").ExecuteTemplate(w, "base", Context{BlackHole:rb,User:user})
		return
	}
	utils.GetTemplate(w, r, "blackhole").ExecuteTemplate(w, "base", Context{BlackHole:rb,User:user})
}
