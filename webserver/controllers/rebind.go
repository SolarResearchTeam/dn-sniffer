package controllers

import (
	"net/http"

	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)

func RebindNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "rebindnew").ExecuteTemplate(w, "base", Default_context{User:user})
}

func RebindEdit(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Rebind *ds.Rebind
		User *ds.Users
	}
	rb, err := models.Database.RebindByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("Webserver(Rebind)", err.Error())
		http.Redirect(w, r, "/rebind", 301)
		return
	}
	utils.GetTemplate(w, r, "rebindedit").ExecuteTemplate(w, "base", Context{Rebind:rb,User:user})
}

func Rebind(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Rebinds *[]ds.Rebind
		User *ds.Users
	}
	rb, err := models.Database.GetAllRebinds()
	if err != nil {
		utils.GetTemplate(w, r, "rebind").ExecuteTemplate(w, "base", Context{Rebinds:rb,User:user})
		return
	}
	utils.GetTemplate(w, r, "rebind").ExecuteTemplate(w, "base", Context{Rebinds:rb,User:user})
}
