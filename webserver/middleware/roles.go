package middleware

import (
	"fmt"
	"net/http"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

// Rights checker
func RequireRights(handler http.HandlerFunc, instances ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value("user")
		if u != nil {
			if u.(*ds.Users).IsLocked {
				session := Storage.Get(r)
				session.Delete(w)
				log.Error("Middleware(Rights)", fmt.Sprintf("LOCKED User: %s", u.(*ds.Users).Username))
				http.Redirect(w, r, "/login?redirect="+r.URL.Path, 301)
				return
			}

			if u.(*ds.Users).PasswordChangeRequired {
				if (r.URL.Path != "/account") && (r.URL.Path != "/api/users/current/pass") {
					log.Error("Middleware(Rights)", fmt.Sprintf("PasswordChangeRequired User: %s", u.(*ds.Users).Username))
					http.Redirect(w, r, "/account", 301)
					return
				}
			}

			for _, instance := range instances {

				//Allowed to all loggedin users
				if instance == "none" {
					handler.ServeHTTP(w, r)
					return
				}

				//Fix missing rigths
				if u.(*ds.Users).Rights == nil {
					scrappy(r)
					u = r.Context().Value("user")
				} else if len(u.(*ds.Users).Rights) == 0 {
					scrappy(r)
					u = r.Context().Value("user")
				} else if _, ok := u.(*ds.Users).Rights[instance]; !ok {
					scrappy_mini(r, instance)
					u = r.Context().Value("user")
				}

				//Check privs
				if u.(*ds.Users).Rights[instance] {
					handler.ServeHTTP(w, r)
					return
				}
			}
			log.Error("Middleware(Rights)", fmt.Sprintf("Rights violation! User: %s, Instances: %+q", u.(*ds.Users).Username, instances))
			http.Redirect(w, r, "/", 301)
			return
		}

		log.Error("Middleware(Rights)", fmt.Sprintf("Unauthorized, Instances: %+q", instances))
		http.Redirect(w, r, "/login?redirect="+r.URL.Path, 301)
		return
	}
}

// Fix if rights map is nil
func scrappy(r *http.Request) {
	u := r.Context().Value("user")
	userdata, err := models.Database.GetUserById(u.(*ds.Users).Id.Hex())
	if err != nil {
		log.Error("Middleware(scrappy)", err.Error())
	}
	//Resore to default
	if userdata.Role == "admin" {
		userdata.Rights = ds.RightsAdmin
	} else {
		userdata.Rights = ds.RightsUser
	}
	_, err = models.Database.EditUser(userdata)
	if err != nil {
		log.Error("Middleware(scrappy)", err.Error())
	}
	u, err = models.Database.GetUserById(userdata.Id.Hex())
	if err != nil {
		log.Error("Middleware(scrappy)", err.Error())
		r = set(r, "user", nil)
	} else {
		log.Error("Middleware(scrappy)", fmt.Sprintf("Success reset rights for user: %s", u.(*ds.Users).Username))
		r = set(r, "user", u)
	}
}

// Fix rigths if one of values is nil
func scrappy_mini(r *http.Request, instance string) {
	u := r.Context().Value("user")
	userdata, err := models.Database.GetUserById(u.(*ds.Users).Id.Hex())
	if err != nil {
		log.Error("Middleware(scrappy_mini)", err.Error())
		r = set(r, "user", nil)
		return
	}
	//Restore to default
	if userdata.Role == "admin" {
		_, ok := ds.RightsAdmin[instance]
		if !ok {
			log.Error("Middleware(scrappy_mini)", fmt.Sprintf("Unknown value: %s", instance))
			r = set(r, "user", nil)
			return
		}
		userdata.Rights[instance] = ds.RightsAdmin[instance]
	} else {
		_, ok := ds.RightsUser[instance]
		if !ok {
			log.Error("Middleware(scrappy_mini)", fmt.Sprintf("Unknown value: %s", instance))
			r = set(r, "user", nil)
			return
		}
		userdata.Rights[instance] = ds.RightsUser[instance]
	}
	_, err = models.Database.EditUser(userdata)
	if err != nil {
		log.Error("Middleware(scrappy_mini)", err.Error())
	}
	u, err = models.Database.GetUserById(userdata.Id.Hex())
	if err != nil {
		log.Error("Middleware(scrappy_mini)", err.Error())
		r = set(r, "user", nil)
	} else {
		log.Error("Middleware(scrappy_mini)", fmt.Sprintf("Success reset rights for user: %s", u.(*ds.Users).Username))
		r = set(r, "user", u)
	}
}
