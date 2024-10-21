package api

import (
	"net/http"
	"regexp"
	"encoding/json"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Create
func Create_rebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Domain 	string `json:"rebind_domain"`
		FromIP 	string `json:"from_ip"`
		ToIP 	string `json:"to_ip"`
		TTL 	string `json:"time"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	rb := ds.Rebind{}
	rb.Domain = req.Domain
	match, _ := regexp.MatchString("^[a-zA-Z0-9-\\.]+$", rb.Domain)
	if match == false {
		json.NewEncoder(w).Encode(Response{Err:"Zone Name incorrect",})
		return
	}
	exist, err := models.Database.RebindExist(rb.Domain)
	if err != nil {
		log.Error("API(Rebind)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	if exist {
		json.NewEncoder(w).Encode(Response{Err:"Rebind Already Exists",})
		return
	}
	rb.FromIP = req.FromIP
	rb.ToIP = req.ToIP
	rb.Time = req.TTL
	_, err = models.Database.RebindNew(&rb)
	if err != nil {
		log.Error("API(Rebind)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/rebind",})
}

//Read
func Read_rebinds(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 			`json:"error"`
		Rebinds []ds.Rebind 	`json:"rebinds"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	rebinds, err := models.Database.GetAllRebinds()
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Rebinds:*rebinds})
}

//Read
func Read_rebind(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 			`json:"error"`
		Rebind  ds.Rebind 		`json:"rebind"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	rebind, err := models.Database.RebindByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Rebind:*rebind})
}

//Update
func Update_rebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Domain 	string `json:"rebind_domain"`
		FromIP 	string `json:"from_ip"`
		ToIP 	string `json:"to_ip"`
		TTL 	string `json:"time"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}


	rb := ds.Rebind{}
	ObjId, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Rebind)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	rb.Id = ObjId
	rb.Domain = req.Domain
	rb.FromIP = req.FromIP
	rb.ToIP = req.ToIP
	rb.Time = req.TTL

	match, _ := regexp.MatchString("^[a-zA-Z0-9-\\.]+$", rb.Domain)
	if match == false {
		json.NewEncoder(w).Encode(Response{Err:"Zone Name incorrect",})
		return
	}
	_, err = models.Database.RebindUpdate(&rb)
	if err != nil {
		log.Error("API(Rebind)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/rebind",})
}

//Delete
func Delete_rebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := models.Database.RebindDelete(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Rebind)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/rebind",})
}