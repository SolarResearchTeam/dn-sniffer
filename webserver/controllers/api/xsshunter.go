package api

import (
	"net/http"
	"regexp"
	"encoding/json"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

//Create
func Create_hunter(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type request struct {
		Name 	string `json:"hunter_name"`
		Domain 	string `json:"primary_domain"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	hn := ds.HunterSetting{}
	hn.Name = req.Name
	if hn.Name == "" {
		json.NewEncoder(w).Encode(Response{Err:"Hunter Name is empty",})
		return
	}
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", hn.Name)
	if match == false {
		http.Error(w, "Hunter Name incorrect", http.StatusBadRequest)
		return
	}
	if xsshunter, err := models.Database.XssHunterByName(hn.Name); !xsshunter.Id.IsZero() {
		if err != nil {
			log.Error("XSSHunter create", err.Error())
			json.NewEncoder(w).Encode(Response{Err:"XSSHunter create",})
			return
		}
		json.NewEncoder(w).Encode(Response{Err:"Hunter Already Exists",})
		return
	}
	proto := "http://"
	if config.Conf.XSSHunter.UseTLS {
		proto = "https://"
	}
	primary_domain := req.Domain
	if primary_domain == "" {
		json.NewEncoder(w).Encode(Response{Err:"Primary domain is empty",})
		return
	}
	match, _ = regexp.MatchString("^[a-zA-Z0-9.:]+$", primary_domain)
	if match == false {
		json.NewEncoder(w).Encode(Response{Err:"Primary domain is incorrect",})
		return
	}
	hn.UUID = uuid.New().String()
	hn.MotherShipToken = uuid.New().String()
	hn.Domain = primary_domain
	hn.MotherShipUrl = proto + primary_domain + "/h/" + hn.Name
	hn.Payload = ds.HunterPayload{
		Name:    "default",
		Payload: utils.DefaultPayload(hn.MotherShipToken, hn.MotherShipUrl, hn.UUID),
	}
	models.Database.XssHunterNew(&hn)
json.NewEncoder(w).Encode(Response{Redirect:"/xsshunter",})
}

//Read
func Read_hunters(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 				`json:"error"`
		Hunters []ds.HunterSetting 	`json:"hunters"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	hunters, err := models.Database.XssHunterAllSettings()
	if err != nil {
		log.Error("API(XSShunter)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Hunters:*hunters})
}

//Read
func Read_hunter(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 				`json:"error"`
		Hunter ds.HunterSetting 	`json:"hunter"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	hunter, err := models.Database.XssHunterGetSettingsByUuid(mux.Vars(r)["uuid"])
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Hunter:*hunter})
}

//Read
func Read_hunter_hits(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 				`json:"error"`
		Hits []ds.HunterHit			`json:"hits"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	hits, err := models.Database.XssHunterGetAllHitsByUUID(mux.Vars(r)["uuid"])
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Hits:*hits})
}

//Update
func Update_hunter(w http.ResponseWriter, r *http.Request) {
}

//Delete
func Delete_hunter(w http.ResponseWriter, r *http.Request) {
	_, err := uuid.Parse(mux.Vars(r)["uuid"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	models.Database.XssHunterDelete(mux.Vars(r)["uuid"])
json.NewEncoder(w).Encode(Response{Redirect:"/xsshunter",})
}

//Clean
func Clear_hunter(w http.ResponseWriter, r *http.Request) {
	_, err := uuid.Parse(mux.Vars(r)["uuid"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	models.Database.XssHunterDeleteHits(mux.Vars(r)["uuid"])
json.NewEncoder(w).Encode(Response{Redirect:"/xsshunter",})
}
