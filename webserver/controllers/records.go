package controllers

import (
	"net/http"

	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)

func Records(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Records *[]ds.Record
		User *ds.Users
	}
	records, err := models.Database.AllRecords()
	if err != nil {
		utils.GetTemplate(w, r, "records").ExecuteTemplate(w, "base", Context{Records:records,User:user})
	}
	utils.GetTemplate(w, r, "records").ExecuteTemplate(w, "base", Context{Records:records,User:user})
}

func RecordsNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "recordsnew").ExecuteTemplate(w, "base", Default_context{User:user})
}

func RecordsEdit(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
		type Context struct {
		Record *ds.Record
		User *ds.Users
	}
	record, err := models.Database.RecordByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("Webserver(Rebind)", err.Error())
		http.Redirect(w, r, "/records", 301)
		return
	}
	utils.GetTemplate(w, r, "recordsedit").ExecuteTemplate(w, "base", Context{Record:record,User:user})
}
