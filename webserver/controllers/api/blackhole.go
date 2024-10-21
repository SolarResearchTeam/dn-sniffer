package api

import (
	"net/http"
	"encoding/json"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)


//Create
func Create_blackhole(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Domain 	string `json:"domain"`
		IP 		string `json:"ip"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}


	rb := ds.BlackHole{}
	rb.Domain = req.Domain
	rb.FromIP = req.IP
	exist, err := models.Database.BlackHoleExist(rb.Domain, rb.FromIP)
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	if exist {
		json.NewEncoder(w).Encode(Response{Err:"BlackHole Already Exists",})
		return
	}

	_, err = models.Database.BlackHoleNew(&rb)
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/blackhole",})
}

//Read
func Read_blackhole(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 				`json:"error"`
		Blackhole ds.BlackHole 		`json:"blackhole"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(response{Error:"Method not allowed",})
		return
	}

	blackhole, err := models.Database.BlackHoleByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Blackhole:*blackhole})
}

//Read
func Read_blackholes(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 				`json:"error"`
		Blackholes []ds.BlackHole 	`json:"blackholes"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(response{Error:"Method not allowed",})
		return
	}

	blackholes, err := models.Database.GetAllBlackHole()
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Blackholes:*blackholes})
}

//Update
func Update_blackhole(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Domain 	string `json:"domain"`
		IP 		string `json:"ip"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	rb := ds.BlackHole{}
	ObjId, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	rb.Id = ObjId
	rb.Domain = req.Domain
	rb.FromIP = req.IP

	_, err = models.Database.BlackHoleUpdate(&rb)
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/blackhole",})
}

//Delete
func Delete_blackhole(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	_, err := models.Database.BlackHoleDelete(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/blackhole",})
}

//Clear
func Clear_blackhole(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	hole, err := models.Database.BlackHoleByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	_, err = models.Database.ZoneCleaner(hole.Domain, hole.FromIP)
	if err != nil {
		log.Error("API(Blackhole)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/blackhole",})
}
