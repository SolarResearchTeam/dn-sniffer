package api

import (
	"net/http"
	"encoding/json"
	"fmt"
	"strconv"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)
type Response struct {
	Err string `json:"error"`
	Redirect string `json:"redirect"`
}

//Create
func Create_zone(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed"})
		return
	}

	type request struct {
		TLD 	string `json:"tld"`
		Name 	string `json:"zone_name"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}
 
	tld := req.TLD
	name := req.Name
	if tld == "" || name == "" {
		json.NewEncoder(w).Encode(Response{Err:"empty params"})
		return
	}

	zn := ds.Zone_settings{}
	if req.Name == "all" {
		zn.Name = uuid.New().String()
	} else {
		zn.Name = name
	}
	zn.TLD = tld
	exist, err := models.Database.TLDExist(zn.TLD)
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error()})
		return
	}
	if exist {
		json.NewEncoder(w).Encode(Response{Err:"Zone TLD Already Exists"})
		return
	}

	_, err = models.Database.ZoneNew(&zn)
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error()})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/zones",})
}

//Read
func Read_zone(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Zone  ds.Zone_settings 		`json:"zone"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	zone, err := models.Database.GetZone(mux.Vars(r)["id"])
		if err != nil {
			log.Error("API(Zone)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}

	json.NewEncoder(w).Encode(response{Zone:*zone})
}

//Read
func Read_zones(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Zones  []ds.Zone 		`json:"zones"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	zn, err := models.Database.GetAllZones()
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	zones := []ds.Zone{}
	for _, zone := range *zn {
		if zone.Name != "other" {
			hits, err := models.Database.GetCountByZone(zone.TLD)
			if err != nil {
				log.Error("API(Zone)", err.Error())
				json.NewEncoder(w).Encode(Response{Err:err.Error(),})
				return
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
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
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
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	zones = append(zones, ds.Zone{
		Id:        "all",
		Name:      "all",
		TLD:       "",
		TotalHits: total_hits,
	})

	json.NewEncoder(w).Encode(response{Zones:zones})
}

//Read
func Read_zones_hits(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Pages int 			`json:"pages"`
		Total  int 			`json:"total"`

		Hits []ds.Hit 		`json:"hits"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Query 	string `json:"q"`
		Limit 	string `json:"limit"`
		Page 	string `json:"page"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	limit, err := strconv.Atoi(req.Limit)
	if (err != nil) || (limit < 1) {
		limit = 100
	}

	query := req.Query
	totalHits := 0
	if query != "" {
		totalHits, err = models.Database.GetCountAllZoneByQuery(query)
		if err != nil {
			log.Error("API(Zone)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	} else {
		totalHits, err = models.Database.GetCountAllZone()
		if err != nil {
			log.Error("API(Zone)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	}

	total_pages := totalHits / limit
	if kek2 := totalHits % limit; kek2 > 0 {
		total_pages = total_pages + 1
	}

	page, err := strconv.Atoi(req.Page)
	if (err != nil) || (page < 1) || (page > total_pages) {
		page = 1
	}

	hits := []ds.Hit{}
	if query != "" {
		hits, err = models.Database.GetAllHitsByQuery(limit, (limit * (page - 1)), query)
		if err != nil {
			log.Error("Webserver(zones)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	} else {
		hits, err = models.Database.GetAllHits(limit, (limit * (page - 1)))
		if err != nil {
			log.Error("Webserver(zones)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	}
	

	json.NewEncoder(w).Encode(response{Hits:hits,Pages:total_pages,Total:totalHits})
}

//Read
func Read_zone_hits(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Pages int 			`json:"pages"`
		Total  int 			`json:"total"`

		Hits []ds.Hit 		`json:"hits"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Query 	string `json:"q"`
		Limit 	string `json:"limit"`
		Page 	string `json:"page"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	id := mux.Vars(r)["id"]
	zone_setts, err := models.Database.GetZone(id)
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error()})
		return
	}
	if zone_setts == nil {
		json.NewEncoder(w).Encode(Response{Err:"No such zone"})
		return
	}

	limit, err := strconv.Atoi(req.Limit)
	if (err != nil) || (limit < 1) {
		limit = 100
	}

	query := req.Query
	totalHits := 0
	if query != "" {
		totalHits, err = models.Database.GetCountByQuery(zone_setts.TLD, query)
		if err != nil {
			log.Error("API(Zone)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	} else {
		totalHits, err = models.Database.GetCountByZone(zone_setts.TLD)
		if err != nil {
			log.Error("API(Zone)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	}

	total_pages := totalHits / limit
	if kek2 := totalHits % limit; kek2 > 0 {
		total_pages = total_pages + 1
	}

	page, err := strconv.Atoi(req.Page)
	if (err != nil) || (page < 1) || (page > total_pages) {
		page = 1
	}

	hits := []ds.Hit{}
	if query != "" {
		hits, err = models.Database.GetHitsByQuery(limit, (limit * (page - 1)), zone_setts.TLD, query)
		if err != nil {
			log.Error("Webserver(zones)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	} else {
		hits, err = models.Database.GetHitsByZone(limit, (limit * (page - 1)), zone_setts.TLD)
		if err != nil {
			log.Error("Webserver(zones)", err.Error())
			json.NewEncoder(w).Encode(Response{Err:err.Error()})
			return
		}
	}
	

	json.NewEncoder(w).Encode(response{Hits:hits,Pages:total_pages,Total:totalHits})
}

//Update
func Update_zone(w http.ResponseWriter, r *http.Request) {
	//TODO
}

//Delete
func Delete_zone(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := models.Database.ZoneDelete(id)
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error()})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/zones",})
}

//Clean
func Clean_zone(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := models.Database.ZoneClean(id)
	if err != nil {
		log.Error("API(Zone)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error()})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/zones",})
}
