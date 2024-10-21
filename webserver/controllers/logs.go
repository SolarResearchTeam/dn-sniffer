package controllers

import (
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
	
	"net/http"
	"strconv"
)


func Logs(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)

	type Context struct {
		Page  int
		Limit int
		Query string

		Total_pages int
		TotalLogs   int

		Logs *[]ds.Log
		User *ds.Users
	}

	page_context := Context{User:user}


	limit, err := strconv.Atoi(r.FormValue("limit"))
	if err == nil {
		page_context.Limit = limit
	} else {
		page_context.Limit = 100
	}

	page_context.Query = r.FormValue("q")

	if page_context.Query != "" {
		page_context.TotalLogs, _ = models.Database.GetLogCountByQuery(page_context.Query)
	} else {
		page_context.TotalLogs, _ = models.Database.GetLogCount()
	}

	page_context.Total_pages = page_context.TotalLogs / page_context.Limit
	if kek2 := page_context.TotalLogs % page_context.Limit; kek2 > 0 {
		page_context.Total_pages = page_context.Total_pages + 1
	}

	page, err := strconv.Atoi(r.FormValue("page"))
	if (err == nil) && (page <= page_context.Total_pages) {
		page_context.Page = page
	} else {
		page_context.Page = 1
	}

	if page_context.Query != "" {
		page_context.Logs, _ = models.Database.GetLogsByQuery(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), page_context.Query)
	} else {
		page_context.Logs, _ = models.Database.GetAllLogs(page_context.Limit, (page_context.Limit * (page_context.Page - 1)))
	}

	utils.GetTemplate(w, r, "logs").ExecuteTemplate(w, "base", page_context)
}
