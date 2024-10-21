package api

import (
	"net/http"
	"encoding/json"
	"strings"
	"net/url"
	"fmt"
	"time"
	"context"
	"crypto/tls"
	"slices"

	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
	oidc "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/oidc"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/utils/smtpsender"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	config "github.com/SolarResearchTeam/dn-sniffer/config"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//Login
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Username 	string `json:"username"`
		Password 	string `json:"password"`
		Redirect 	string `json:"redirect"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	username := req.Username
	password := req.Password
	redirect := req.Redirect

	if !utils.RegExChecker(username, "username") {
		json.NewEncoder(w).Encode(Response{Err:"Bad username",})
		return
	}
	//Getting userdata by username. We consider it to be unique
	userdata, err := models.Database.GetUserByName(username)
	if err != nil {
		log.Error("Webserver(General_Database.GetUserByName)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	//If locked don't even bother check password
	if userdata.IsLocked {
		msg := "User locked, contact admin"
		json.NewEncoder(w).Encode(Response{Err:msg,})
		return
	}
	//Constant time comparison of passwords
	if bcrypt.CompareHashAndPassword([]byte(userdata.Password), []byte(password)) == nil {
		session := mid.Storage.Get(r)
		session.Values["id"] = userdata.Id.Hex()
		session.Values["user"] = userdata
		session.Save(w)
		u, err := url.Parse(redirect)
		if err != nil {
			json.NewEncoder(w).Encode(Response{Redirect:"/",})
			return
		} else {
			json.NewEncoder(w).Encode(Response{Redirect:"/"+strings.TrimPrefix(u.Path,"/"),})
			return
		}
	} else {
		msg := "Login or password incorrect"
		json.NewEncoder(w).Encode(Response{Err:msg,})
	}

}

//OAuth2 callback
func OIDCcallback(w http.ResponseWriter, r *http.Request) {
	session := mid.Storage.Get(r)
	orig_state := session.Values["state"]
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if state == "" {
		json.NewEncoder(w).Encode(Response{Err:"Empty state",})
		return
	}
	if state != orig_state {
		json.NewEncoder(w).Encode(Response{Err:"State missmatch",})
		return
	}
	if code == "" {
		json.NewEncoder(w).Encode(Response{Err:"Empty code",})
		return
	}

	oidcConfig, err := oidc.GetOIDCConfigInstance()
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad oidcConfig",})
		log.Error("OIDCcallback",err.Error())
		return
	}

	ctx := context.Background()
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    sslcli := &http.Client{Transport: tr}
    ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)

	token, err := oidcConfig.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad code",})
		log.Error("OIDCcallback",err.Error())
		return
	}

	idToken, err := oidcConfig.Verifier.Verify(ctx, token.Extra("id_token").(string))
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Failed to verify ID token",})
		log.Error("OIDCcallback",err.Error())
		return
	}

	type Claim struct {
		Username 	string 		`json:"preferred_username"`
		LastName 	string 		`json:"family_name"`
		FirstName 	string 		`json:"given_name"`
		Email 		string 		`json:"email"`
		Roles 		[]string 	`json:"roles"`
	}


	claims := Claim{}
	if err := idToken.Claims(&claims); err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Failed to parse claims",})
		log.Error("OIDCcallback",err.Error())
		return
	}
	//Getting userdata by username. We consider it to be unique
	userdata, err := models.Database.GetUserByName(claims.Username)
	if err != nil {
		log.Error("OIDCcallback(General_Database.GetUserByName)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}

	if userdata.Id.IsZero() {
		if config.Conf.OIDC.CreateUsers {
			new_userdata := ds.Users{}
			new_userdata.Email = claims.Email
			new_userdata.Username = claims.Username
			new_userdata.Id = primitive.NewObjectID()
			new_userdata.FirstName = claims.FirstName
			new_userdata.LastName = claims.LastName
			new_userdata.Password = "none"

			if slices.Contains(claims.Roles,"admin") {
				new_userdata.Role = "admin"
				new_userdata.Rights = ds.RightsAdmin
			} else if slices.Contains(claims.Roles,"user") {
				new_userdata.Role = "user"
				new_userdata.Rights = ds.RightsUser
			} else {
				new_userdata.Role = "custom"
				new_userdata.Rights = ds.RightsAnonymous
			}

			_, err = models.Database.AddUser(&new_userdata)
			if err != nil {
				log.Error("OIDCcallback(AddUser)", err.Error())
				json.NewEncoder(w).Encode(Response{Err:err.Error(),})
				return
			}

			userdata, err = models.Database.GetUserByName(claims.Username)
			if err != nil {
				log.Error("OIDCcallback(General_Database.GetUserByName)", err.Error())
				json.NewEncoder(w).Encode(Response{Err:err.Error(),})
				return
			}
		} else {
			json.NewEncoder(w).Encode(Response{Err:"No such user",})
			return
		}
	}

	//If locked don't even bother check password
	if userdata.IsLocked {
		msg := "User locked, contact admin"
		json.NewEncoder(w).Encode(Response{Err:msg,})
		return
	}
	session.Values["id"] = userdata.Id.Hex()
	session.Values["user"] = userdata
	session.Save(w)

	json.NewEncoder(w).Encode(Response{Redirect:session.Values["redirect"].(string),})
	return
}

//Logout
func Logout(w http.ResponseWriter, r *http.Request) {
	session := mid.Storage.Get(r)
	session.Delete(w)
	json.NewEncoder(w).Encode(Response{Redirect:"/login",})
}

//Restore
func Restore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Email 	string `json:"username"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	user, err := models.Database.GetUserByEmail(req.Email)
	if err != nil {
		log.Error("Webserver(Restore)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:err.Error(),})
		return
	}
	if user.Id.IsZero() {
		json.NewEncoder(w).Encode(Response{Err:"User not found",})
		return
	}
	user.RestoreToken = uuid.New().String()
	user.RestoreTokenDate = time.Now().Format(time.RFC3339)
	_, err = models.Database.EditUser(user)
	message := fmt.Sprintf(smtpsender.RestorePassword, smtpsender.SMTPSender.From, user.Email, smtpsender.SMTPSender.URL+user.RestoreToken)
	smtpsender.SMTPSender.SendMessage(user.Email, message)
	if err != nil {
		log.Error("Webserver(Users)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:"Failed to send",})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect:"/login",})
}


//Restore
func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Token 	string `json:"restoretoken"`
		Password 	string `json:"password"`
		Confirm 	string `json:"confirm"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	if req.Token == "" {
		json.NewEncoder(w).Encode(Response{Redirect:"/login",})
		return
	}
	user, err := models.Database.GetUserByRestoreToken(req.Token)
	if err != nil {
		log.Error("Webserver(RestoreSetNewPassword)", err.Error())
		json.NewEncoder(w).Encode(Response{Err:"Failed to find",})
		return
	}
	if user.Id.IsZero() {
		json.NewEncoder(w).Encode(Response{Err:"Unknown token",})
		return
	}
	if user.IsLocked {
		json.NewEncoder(w).Encode(Response{Err:"User locked",})
		return
	}
	restoredate, err := time.Parse(time.RFC3339, user.RestoreTokenDate)
	if err != nil {
		log.Error("Webserver(RestoreSetNewPassword)", err.Error())
		json.NewEncoder(w).Encode(Response{Redirect:"/login",})
		return
	}
	now := time.Now()
	if now.Sub(restoredate) > 1*time.Hour {
		user.RestoreToken = ""
		user.RestoreTokenDate = ""
		_, err = models.Database.EditUser(user)
		json.NewEncoder(w).Encode(Response{Err:"Unknown token",})
		return
	}
	if req.Password != req.Confirm {
		json.NewEncoder(w).Encode(Response{Err:"Passwords dont match",})
		return
	}
	user.PasswordChangeRequired = false
	user.Password, _ = utils.GeneratePasswordHash(req.Password)
	user.RestoreToken = ""
	_, err = models.Database.EditUser(user)
	if err != nil {
		log.Error("Webserver(RestoreSetNewPassword)", err.Error())
		json.NewEncoder(w).Encode(Response{Redirect:"/login",})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect:"/login",})
}