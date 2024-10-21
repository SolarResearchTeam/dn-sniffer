package api

import (
	"encoding/json"
	"net/http"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// Create
func Create_user(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	type request struct {
		Email      string            `json:"email"`
		Username   string            `json:"username"`
		Role       string            `json:"role"`
		FirstName  string            `json:"first_name"`
		LastName   string            `json:"last_name"`
		Password   string            `json:"password"`
		Rights     map[string]string `json:"rights"`
		Locked     string            `json:"locked"`
		ChangePass string            `json:"passwordchangerequired"`

		Bicycle
	}

	var req request
	req.Bicycle = Bicycle{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	//I WANT TO RIDE MY BICYCLE
	req.Rights = req.ToRights()

	if req.Username == "" || req.Password == "" || req.Email == "" || req.Role == "" {
		json.NewEncoder(w).Encode(Response{Err: "Invalid user data"})
		return
	}
	userdata := ds.Users{}
	userdata.Email = req.Email
	userdata.Username = req.Username
	userdata.Role = req.Role
	userdata.Id = primitive.NewObjectID()
	userdata.FirstName = req.FirstName
	userdata.LastName = req.LastName
	userdata.Password, _ = utils.GeneratePasswordHash(req.Password)

	if userdata.Role == "admin" {
		userdata.Rights = ds.RightsAdmin
	} else if userdata.Role == "user" {
		userdata.Rights = ds.RightsUser
	} else {
		userdata.Role = "custom"
		userdata.Rights = ds.RightsAnonymous
		for name, _ := range userdata.Rights {
			if req.Rights[name] != "" {
				userdata.Rights[name] = true
			}
		}
	}

	if req.Locked != "" {
		userdata.IsLocked = true
	}
	if req.ChangePass != "" {
		userdata.PasswordChangeRequired = true
	}
	_, err = models.Database.AddUser(&userdata)
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/users"})
}

// Read
func Read_user(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string   `json:"error"`
		User  ds.Users `json:"user"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	user, err := models.Database.GetUserById(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	if user.Id.IsZero() {
		json.NewEncoder(w).Encode(Response{Err: "User not found"})
		return
	}

	json.NewEncoder(w).Encode(response{User: *user})
}

// Read
func Read_users(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string     `json:"error"`
		Users []ds.Users `json:"users"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	users, err := models.Database.GetAllUsers()
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(response{Users: *users})
}

// Update
func Update_user(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	type request struct {
		Email      string            `json:"email"`
		Username   string            `json:"username"`
		Role       string            `json:"role"`
		FirstName  string            `json:"first_name"`
		LastName   string            `json:"last_name"`
		Password   string            `json:"password"`
		Confirm    string            `json:"confirm"`
		Rights     map[string]string `json:"rights"`
		Locked     string            `json:"locked"`
		ChangePass string            `json:"passwordchangerequired"`

		Bicycle
	}

	var req request
	req.Bicycle = Bicycle{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	//I WANT TO RIDE MY BICYCLE
	req.Rights = req.ToRights()

	if req.Username == "" || req.Email == "" || req.Role == "" {
		json.NewEncoder(w).Encode(Response{Err: "Invalid user data"})
		return
	}
	userdata, err := models.Database.GetUserById(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	if userdata.Id.IsZero() {
		json.NewEncoder(w).Encode(Response{Err: "User not found"})
		return
	}

	userdata.Email = req.Email
	userdata.Username = req.Username
	userdata.Role = req.Role
	userdata.FirstName = req.FirstName
	userdata.LastName = req.LastName
	if req.Password != "" && req.Confirm != "" && req.Confirm == req.Password {
		userdata.Password, _ = utils.GeneratePasswordHash(req.Password)
	}

	if userdata.Role == "admin" {
		userdata.Rights = ds.RightsAdmin
	} else if userdata.Role == "user" {
		userdata.Rights = ds.RightsUser
	} else {
		userdata.Role = "custom"
		userdata.Rights = ds.RightsAnonymous
		for name, _ := range userdata.Rights {
			if req.Rights[name] != "" {
				userdata.Rights[name] = true
			}
		}
	}

	if req.Locked != "" {
		userdata.IsLocked = true
	}
	if req.ChangePass != "" {
		userdata.PasswordChangeRequired = true
	}
	_, err = models.Database.EditUser(userdata)
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/users"})
}

// Delete
func Delete_user(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	user, err := models.Database.GetUserById(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	if user.Id.IsZero() {
		json.NewEncoder(w).Encode(Response{Err: "Invalid user ID"})
		return
	}
	_, err = models.Database.UserDelete(mux.Vars(r)["id"])
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/users"})
}

// Read
func Current_user(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string   `json:"error"`
		User  ds.Users `json:"user"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	u := r.Context().Value("user").(*ds.Users)
	json.NewEncoder(w).Encode(response{User: *u})
}

// Update
func Current_user_pass(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	u := r.Context().Value("user").(*ds.Users)
	if u.IsLocked {
		json.NewEncoder(w).Encode(Response{Err: "User locked"})
		return
	}

	type request struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
		Confirm     string `json:"confirm"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	//Constant time comparison of passwords
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)) != nil {
		json.NewEncoder(w).Encode(Response{Err: "Wrong old password"})
		return
	}
	if req.NewPassword != req.Confirm {
		json.NewEncoder(w).Encode(Response{Err: "New passwords missmatch"})
		return
	}
	u.PasswordChangeRequired = false
	u.Password, _ = utils.GeneratePasswordHash(req.NewPassword)
	_, err = models.Database.EditUser(u)
	if err != nil {
		log.Error("API(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	session := mid.Storage.Get(r)
	session.Delete(w)
	json.NewEncoder(w).Encode(Response{Redirect: "/login"})
}

type Bicycle struct {
	Zones_view               string `json:"zones_view"`
	Zone_view                string `json:"zone_view"`
	Zones_edit               string `json:"zones_edit"`
	Zone_edit                string `json:"zone_edit"`
	Zone_create              string `json:"zone_create"`
	Zone_delete              string `json:"zone_delete"`
	Zone_clean               string `json:"zone_clean"`
	Rebind_view              string `json:"rebind_view"`
	Rebind_edit              string `json:"rebind_edit"`
	Rebind_create            string `json:"rebind_create"`
	Rebind_delete            string `json:"rebind_delete"`
	Blackhole_view           string `json:"blackhole_view"`
	Blackhole_edit           string `json:"blackhole_edit"`
	Blackhole_create         string `json:"blackhole_create"`
	Blackhole_delete         string `json:"blackhole_delete"`
	Blackhole_clean          string `json:"blackhole_clean"`
	Records_view             string `json:"records_view"`
	Record_edit              string `json:"record_edit"`
	Record_create            string `json:"record_create"`
	Record_delete            string `json:"record_delete"`
	Interacts_view           string `json:"interacts_view"`
	Interact_view            string `json:"interact_view"`
	Interacts_share          string `json:"interacts_share"`
	Interact_edit            string `json:"interact_edit"`
	Interact_edit_config     string `json:"interact_edit_config"`
	Interact_create          string `json:"interact_create"`
	Interact_delete          string `json:"interact_delete"`
	Interact_clean           string `json:"interact_clean"`
	Interact_run             string `json:"interact_run"`
	Xsshunters_view          string `json:"xsshunters_view"`
	Xsshunter_view           string `json:"xsshunter_view"`
	Xsshunter_payload_view   string `json:"xsshunter_payload_view"`
	Xsshunter_payload_create string `json:"xsshunter_payload_create"`
	Xsshunter_edit           string `json:"xsshunter_edit"`
	Xsshunter_create         string `json:"xsshunter_create"`
	Xsshunter_delete         string `json:"xsshunter_delete"`
	Xsshunter_clean          string `json:"xsshunter_clean"`
	Users_list               string `json:"users_list"`
	User_edit                string `json:"user_edit"`
	User_create              string `json:"user_create"`
	User_delete              string `json:"user_delete"`
	Account_view             string `json:"account_view"`
	Logs                     string `json:"logs"`
	Certs                    string `json:"certs"`
}

func (b *Bicycle) ToRights() map[string]string {
	rights := make(map[string]string)
	rights["zones_view"] = b.Zones_view
	rights["zone_view"] = b.Zone_view
	rights["zones_edit"] = b.Zones_edit
	rights["zone_edit"] = b.Zone_edit
	rights["zone_create"] = b.Zone_create
	rights["zone_delete"] = b.Zone_delete
	rights["zone_clean"] = b.Zone_clean
	rights["rebind_view"] = b.Rebind_view
	rights["rebind_edit"] = b.Rebind_edit
	rights["rebind_create"] = b.Rebind_create
	rights["rebind_delete"] = b.Rebind_delete
	rights["blackhole_view"] = b.Blackhole_view
	rights["blackhole_edit"] = b.Blackhole_edit
	rights["blackhole_create"] = b.Blackhole_create
	rights["blackhole_delete"] = b.Blackhole_delete
	rights["blackhole_clean"] = b.Blackhole_clean
	rights["records_view"] = b.Records_view
	rights["record_edit"] = b.Record_edit
	rights["record_create"] = b.Record_create
	rights["record_delete"] = b.Record_delete
	rights["interacts_view"] = b.Interacts_view
	rights["interact_view"] = b.Interact_view
	rights["interacts_share"] = b.Interacts_share
	rights["interact_edit"] = b.Interact_edit
	rights["interact_edit_config"] = b.Interact_edit_config
	rights["interact_create"] = b.Interact_create
	rights["interact_delete"] = b.Interact_delete
	rights["interact_clean"] = b.Interact_clean
	rights["interact_run"] = b.Interact_run
	rights["xsshunters_view"] = b.Xsshunters_view
	rights["xsshunter_view"] = b.Xsshunter_view
	rights["xsshunter_payload_view"] = b.Xsshunter_payload_view
	rights["xsshunter_payload_create"] = b.Xsshunter_payload_create
	rights["xsshunter_edit"] = b.Xsshunter_edit
	rights["xsshunter_create"] = b.Xsshunter_create
	rights["xsshunter_delete"] = b.Xsshunter_delete
	rights["xsshunter_clean"] = b.Xsshunter_clean
	rights["users_list"] = b.Users_list
	rights["user_edit"] = b.User_edit
	rights["user_create"] = b.User_create
	rights["user_delete"] = b.User_delete
	rights["account_view"] = b.Account_view
	rights["logs"] = b.Logs
	rights["certs"] = b.Certs
	return rights
}
