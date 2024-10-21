package controllers

import (
	"fmt"
	"net/http"
	"time"

	
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/utils/smtpsender"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func Users(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Users *[]ds.Users
		User *ds.Users
	}
	users, err := models.Database.GetAllUsers()
	if err != nil {
		utils.GetTemplate(w, r, "users").ExecuteTemplate(w, "base", Context{Users:users,User:user})
		return
	}
	utils.GetTemplate(w, r, "users").ExecuteTemplate(w, "base", Context{Users:users,User:user})
}

func UsersEdit(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		UserEdit *ds.Users
		User *ds.Users
	}
	useredit, err := models.Database.GetUserById(mux.Vars(r)["id"])
	if err != nil {
		log.Error("Webserver(Users)", err.Error())
		http.Redirect(w, r, "/users", 301)
		return
	}
	utils.GetTemplate(w, r, "usersedit").ExecuteTemplate(w, "base", Context{UserEdit:useredit,User:user})
}

func UsersNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Rights map[string]bool
		User *ds.Users
	}
	utils.GetTemplate(w, r, "usersnew").ExecuteTemplate(w, "base", Context{Rights:ds.RightsUser,User:user})
}

func Restore(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		utils.GetTemplate(w, r, "restore").ExecuteTemplate(w, "base", nil)
	}
	if r.Method == "POST" {
		user, err := models.Database.GetUserByEmail(r.FormValue("email"))
		if err != nil {
			log.Error("Webserver(Restore)", err.Error())
			http.Redirect(w, r, "/restore", 301)
			return
		}
		if user.Id.IsZero() {
			http.Redirect(w, r, "/restore", 301)
			return
		}
		user.RestoreToken = uuid.New().String()
		user.RestoreTokenDate = time.Now().Format(time.RFC3339)
		_, err = models.Database.EditUser(user)
		message := fmt.Sprintf(smtpsender.RestorePassword, smtpsender.SMTPSender.From, user.Email, smtpsender.SMTPSender.URL+user.RestoreToken)
		smtpsender.SMTPSender.SendMessage(user.Email, message)
		if err != nil {
			log.Error("Webserver(Users)", err.Error())
			http.Redirect(w, r, "/restore", 301) 
			return
		}
		http.Redirect(w, r, "/login", 301)
	}
}

func RestoreSetNewPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if mux.Vars(r)["restoretoken"] == "" {
			http.Redirect(w, r, "/login", 301)
			return
		}
		user, err := models.Database.GetUserByRestoreToken(mux.Vars(r)["restoretoken"])
		if err != nil {
			log.Error("Webserver(RestoreSetNewPassword)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		if user.Id.IsZero() {
			http.Redirect(w, r, "/login", 301)
			return
		}
		restoredate, err := time.Parse(time.RFC3339, user.RestoreTokenDate)
		if err != nil {
			log.Error("Webserver(RestoreSetNewPassword)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		now := time.Now()
		if now.Sub(restoredate) > 1*time.Hour {
			user.RestoreToken = ""
			user.RestoreTokenDate = ""
			_, err = models.Database.EditUser(user)
			http.Redirect(w, r, "/login", 301)
			return
		}
		utils.GetTemplate(w, r, "userrestoresetpassword").ExecuteTemplate(w, "base", mux.Vars(r)["restoretoken"])
	}
	if r.Method == "POST" {
		if mux.Vars(r)["restoretoken"] == "" {
			http.Redirect(w, r, "/login", 301)
			return
		}
		user, err := models.Database.GetUserByRestoreToken(mux.Vars(r)["restoretoken"])
		if err != nil {
			log.Error("Webserver(RestoreSetNewPassword)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		if user.Id.IsZero() {
			http.Redirect(w, r, "/login", 301)
			return
		}
		if user.IsLocked {
			http.Redirect(w, r, "/login", 403)
			return
		}
		restoredate, err := time.Parse(time.RFC3339, user.RestoreTokenDate)
		if err != nil {
			log.Error("Webserver(RestoreSetNewPassword)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		now := time.Now()
		if now.Sub(restoredate) > 1*time.Hour {
			user.RestoreToken = ""
			user.RestoreTokenDate = ""
			_, err = models.Database.EditUser(user)
			http.Redirect(w, r, "/login", 301)
			return
		}
		if r.FormValue("password") != r.FormValue("confirm") {
			http.Redirect(w, r, "/restore/"+mux.Vars(r)["restoretoken"], http.StatusTeapot)
			return
		}
		user.PasswordChangeRequired = false
		user.Password, _ = utils.GeneratePasswordHash(r.FormValue("password"))
		user.RestoreToken = ""
		_, err = models.Database.EditUser(user)
		if err != nil {
			log.Error("Webserver(RestoreSetNewPassword)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		http.Redirect(w, r, "/login", 301)
	}
}
