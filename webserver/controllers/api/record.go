package api

import (
	"net/http"
	"slices"
	"strings"
	"encoding/json"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Create
func Create_record(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		TLD 	string `json:"tld"`
		Type 	string `json:"type"`
		Value 	string `json:"value"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	rc := ds.Record{}
	rc.TLD = req.TLD
	dns_type := req.Type
	if validate_type(dns_type) {
		rc.Type = dns_type
	} else {
		rc.Type = "TXT"
	}
	  
	value := req.Value
	if len(value) > 256 {
		rc.Value = value[:255]
	} else {
		rc.Value = value
	}


	_, err = models.Database.RecordAdd(&rc)
	if err != nil {
		log.Error("API(Record)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/records",})

}

//Read
func Read_records(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Records []ds.Record 	`json:"records"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	records, err := models.Database.AllRecords()
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Records:*records})
}

//Read
func Read_record(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Record ds.Record 	`json:"record"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}
	record, err := models.Database.RecordByID(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error:err.Error(),})
		return
	}

	json.NewEncoder(w).Encode(response{Record:*record})
}

//Update
func Update_record(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		TLD 	string `json:"tld"`
		Type 	string `json:"type"`
		Value 	string `json:"value"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	ObjId, err := primitive.ObjectIDFromHex(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Record)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	rc := ds.Record{}
	rc.Id = ObjId
	rc.TLD = req.TLD

	dns_type := req.Type
	if validate_type(dns_type) {
		rc.Type = dns_type
	} else {
		rc.Type = "TXT"
	}
	  
	value := req.Value
	if len(value) > 256 {
		rc.Value = value[:255]
	} else {
		rc.Value = value
	}
	

	_, err = models.Database.RecordEdit(&rc)
	if err != nil {
		log.Error("API(Record)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/records",})
}

//Delete
func Delete_record(w http.ResponseWriter, r *http.Request) {
	rec_id := mux.Vars(r)["id"]
	_, err := models.Database.RecordDelete(rec_id)
	if err != nil {
		log.Error("API(Record)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
json.NewEncoder(w).Encode(Response{Redirect:"/records",})
}

var types = []string{"A", "NS", "CNAME", "SOA", "PTR", "AAAA", "TXT", "MX"}

func validate_type(dns_type string) bool {
	return slices.Contains(types, strings.ToUpper(dns_type))
}