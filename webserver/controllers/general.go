package controllers

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"crypto/tls"
	"context"
	"slices"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
	oidc "github.com/SolarResearchTeam/dn-sniffer/webserver/utils/oidc"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	config "github.com/SolarResearchTeam/dn-sniffer/config"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

type Default_context struct {
	User *ds.Users
}

func Main(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		User         *ds.Users
		DNSHits      int
		XSSHits      int
		InteractHits int
	}

	zn, err := models.Database.GetAllZones()
	if err != nil {
		log.Error("Webserver(Welcome)", err.Error())
	}
	totalhits := 0
	for _, zone := range *zn {
		if zone.Name != "other" {
			hits, err := models.Database.GetCountByZone(zone.TLD)
			if err != nil {
				log.Error("Webserver(Welcome)", err.Error())
			}
			totalhits = totalhits + hits
		}
	}
	interacthits, _ := models.Database.GetInteractHitsCount()
	xsshunterhits, _ := models.Database.GetXssHunterHitsCount()
	utils.GetTemplate(w, r, "welcome").ExecuteTemplate(w, "base", Context{XSSHits: xsshunterhits, InteractHits: interacthits, DNSHits: totalhits, User: user})
}

func Account(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "account").ExecuteTemplate(w, "base", Default_context{User: user})
}

func OAuth2(w http.ResponseWriter, r *http.Request) {
	redirect := r.FormValue("redirect")
	u, err := url.Parse(redirect)
	if err != nil {
		redirect = "/"
	} else {
		redirect = "/"+strings.TrimPrefix(u.Path,"/")
	}
	state := uuid.New().String()

	session := mid.Storage.Get(r)
	session.Values["redirect"] = redirect
	session.Values["state"] = state
	session.Save(w)

	oidcConfig, err := oidc.GetOIDCConfigInstance()
	if err != nil {
		type Context struct {
			Msg string
			Redirect string
		}
		templates := template.New("template")
		_, err2 := templates.ParseFiles("templates/login.html")
		if err2 != nil {
			log.Error("WebServer (Login)", err2.Error())
		}
		template.Must(templates, err2).ExecuteTemplate(w, "base", Context{Msg:err.Error(),Redirect:redirect})
		return
	}
	loginURL := oidcConfig.LoginURL(state)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func Login(w http.ResponseWriter, r *http.Request) {
	type Context struct {
		OAuth2 bool
		OAuth2Provider string
		Msg string
		Redirect string
	}
	oauth2_enabled := config.Conf.OIDC.Enabled
	oauth2_name := config.Conf.OIDC.Provider_Name

	templates := template.New("template")
	_, err := templates.ParseFiles("templates/login.html")
	if err != nil {
		log.Error("WebServer (Login)", err.Error())
	}
	var msg string
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}



	if r.Method == "GET" {
		if r.Context().Value("user") != nil {
			http.Redirect(w, r, "/", 301)
		}
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Redirect:redirect})
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if !utils.RegExChecker(username, "username") {
			msg = "Bad username"
			template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:msg,Redirect:redirect})
			return
		}
		//Getting userdata by username. We consider it to be unique
		userdata, err := models.Database.GetUserByName(username)
		if err != nil {
			log.Error("Webserver(General_Database.GetUserByName)", err.Error())
			http.Redirect(w, r, "/login", 301)
			return
		}
		//If locked don't even bother check password
		if userdata.IsLocked {
			msg = "User locked, contact admin"
			template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:msg,Redirect:redirect})
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
				http.Redirect(w, r, "/", 301)
			} else {
				http.Redirect(w, r, "/"+strings.TrimPrefix(u.Path,"/"), 301)
			}
		} else {
			msg = "Login or password incorrect"
			template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:msg,Redirect:redirect})
		}
	}
	return
}

//OAuth2 callback
func OIDCcallback(w http.ResponseWriter, r *http.Request) {
	type Context struct {
		OAuth2 bool
		OAuth2Provider string
		Msg string
		Redirect string
	}
	oauth2_enabled := config.Conf.OIDC.Enabled
	oauth2_name := config.Conf.OIDC.Provider_Name

	templates := template.New("template")
	_, err := templates.ParseFiles("templates/login.html")
	if err != nil {
		log.Error("WebServer (Login)", err.Error())
	}

	session := mid.Storage.Get(r)
	orig_state := session.Values["state"].(string)
	redirect := session.Values["redirect"].(string)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if state == "" {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Empty state",Redirect:redirect})
		return
	}
	if state != orig_state {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"State missmatch",Redirect:redirect})
		return
	}
	if code == "" {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Empty code",Redirect:redirect})
		return
	}

	oidcConfig, err := oidc.GetOIDCConfigInstance()
	if err != nil {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Bad oidcConfig",Redirect:redirect})
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
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Bad code",Redirect:redirect})
		log.Error("OIDCcallback",err.Error())
		return
	}

	idToken, err := oidcConfig.Verifier.Verify(ctx, token.Extra("id_token").(string))
	if err != nil {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Failed to verify ID token",Redirect:redirect})
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
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Failed to parse claims",Redirect:redirect})
		log.Error("OIDCcallback",err.Error())
		return
	}

	//Getting userdata by username. We consider it to be unique
	userdata, err := models.Database.GetUserByName(claims.Username)
	if err != nil {
		log.Error("OIDCcallback(General_Database.GetUserByName)", err.Error())
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Failed to get user",Redirect:redirect})
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
				template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Failed to add user",Redirect:redirect})
				return
			}

			userdata, err = models.Database.GetUserByName(claims.Username)
			if err != nil {
				log.Error("OIDCcallback(General_Database.GetUserByName)", err.Error())
				template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"Failed to get user",Redirect:redirect})
		return
			}
		} else {
			template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"User not registered",Redirect:redirect})
			return
		}
	}

	//If locked don't even bother check password
	if userdata.IsLocked {
		template.Must(templates, err).ExecuteTemplate(w, "base", Context{OAuth2:oauth2_enabled,OAuth2Provider:oauth2_name,Msg:"User locked, contact admin",Redirect:redirect})
		return
	}
	session.Values["id"] = userdata.Id.Hex()
	session.Values["user"] = userdata
	session.Save(w)

	http.Redirect(w, r, redirect, 301)
	return
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session := mid.Storage.Get(r)
	session.Delete(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}
