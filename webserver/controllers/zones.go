package controllers

import (
	"fmt"
	"net/http"
	"strconv"

	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/config"

	"github.com/gorilla/mux"
)

func ZoneNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "zonenew").ExecuteTemplate(w, "base", Default_context{User:user})
}

func Zones(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Zones *[]ds.Zone
		User *ds.Users
	}

	zn, err := models.Database.GetAllZones()
	if err != nil {
		log.Error("Webserver(Zones)", err.Error())
	}
	zones := []ds.Zone{}
	for _, zone := range *zn {
		if zone.Name != "other" {
			hits, err := models.Database.GetCountByZone(zone.TLD)
			if err != nil {
				log.Error("Webserver(Zones)", err.Error())
			}
			zones = append(zones, ds.Zone{
				Id:        zone.Id.Hex(),
				Name:      zone.Name,
				TLD:       zone.TLD,
				TotalHits: hits,
			})
		}
	}

	hits, err := models.Database.GetCountByZone("other")
	if err != nil {
		log.Error("Webserver(Zones)", err.Error())
	}
	zones = append(zones, ds.Zone{
		Id:        "other",
		Name:      "other",
		TLD:       fmt.Sprintf("<not_registred> %s", config.Conf.DNS.PrimaryZone),
		TotalHits: hits,
	})

	total_hits, err := models.Database.GetCountAllZone()
	if err != nil {
		log.Error("Webserver(Zones)", err.Error())
	}
	zones = append(zones, ds.Zone{
		Id:        "all",
		Name:      "all",
		TLD:       "",
		TotalHits: total_hits,
	})

	utils.GetTemplate(w, r, "zones").ExecuteTemplate(w, "base", Context{Zones:&zones,User:user})
}

func Hits(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)

	type Context struct {
		Page  int
		Limit int
		Query string

		Total_pages int
		TotalHits   int

		Id   string
		Name string
		TLD  string

		Hits []ds.Hit
		User *ds.Users
	}

	page_context := Context{User:user}

	id := mux.Vars(r)["id"]
	if id != "all" && id != "other" {
		zone_setts, err := models.Database.GetZone(id)
		if err != nil {
			log.Error("Webserver(Zones)", err.Error())
			http.Redirect(w, r, "/zones", 301)
			return
		}
		if zone_setts == nil {
			http.Redirect(w, r, "/zones", 301)
			return
		}
		page_context.Id = zone_setts.Id.Hex()
		page_context.Name = zone_setts.Name
		page_context.TLD = zone_setts.TLD
	} else {
		page_context.Id = id
		page_context.Name = id
		page_context.TLD = id
	}

	limit, err := strconv.Atoi(r.FormValue("limit"))
	if err == nil {
		page_context.Limit = limit
	} else {
		page_context.Limit = 100
	}

	page_context.Query = r.FormValue("q")
	if id != "all" {
		if page_context.Query != "" {
			page_context.TotalHits, err = models.Database.GetCountByQuery(page_context.TLD, page_context.Query)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		} else {
			page_context.TotalHits, err = models.Database.GetCountByZone(page_context.TLD)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		}
	} else {
		if page_context.Query != "" {
			page_context.TotalHits, err = models.Database.GetCountAllZoneByQuery(page_context.Query)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		} else {
			page_context.TotalHits, err = models.Database.GetCountAllZone()
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		}
	}

	page_context.Total_pages = page_context.TotalHits / page_context.Limit
	if kek2 := page_context.TotalHits % page_context.Limit; kek2 > 0 {
		page_context.Total_pages = page_context.Total_pages + 1
	}

	page, err := strconv.Atoi(r.FormValue("page"))
	if (err == nil) && (page <= page_context.Total_pages) {
		page_context.Page = page
	} else {
		page_context.Page = 1
	}

	page_context.Query = r.FormValue("q")
	if id != "all" {
		if page_context.Query != "" {
			page_context.Hits, err = models.Database.GetHitsByQuery(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), page_context.TLD, page_context.Query)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		} else {
			page_context.Hits, err = models.Database.GetHitsByZone(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), page_context.TLD)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		}
	} else {
		if page_context.Query != "" {
			page_context.Hits, err = models.Database.GetAllHitsByQuery(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), page_context.Query)
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		} else {
			page_context.Hits, err = models.Database.GetAllHits(page_context.Limit, (page_context.Limit * (page_context.Page - 1)))
			if err != nil {
				log.Error("Webserver(zones)", err.Error())
				http.Redirect(w, r, "/zones", 301)
				return
			}
		}
	}

	utils.GetTemplate(w, r, "hits").ExecuteTemplate(w, "base", page_context)
}
