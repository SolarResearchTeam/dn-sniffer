package manager

import (
	"net/http"

	controllers "github.com/SolarResearchTeam/dn-sniffer/webserver/controllers"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)


func new_admin_handler() http.HandlerFunc {
	router := mux.NewRouter()
	router = router.StrictSlash(true)
	
	//Base routes
	router.HandleFunc("/", mid.RequireRights(controllers.Main, "none"))
	router.HandleFunc("/login", controllers.Login)
	router.HandleFunc("/oauth", controllers.OAuth2)
	router.HandleFunc("/oauth/callback", controllers.OIDCcallback)
	router.HandleFunc("/logout", mid.RequireRights(controllers.Logout, "none"))
	
	//User/account related
	router.HandleFunc("/account", mid.RequireRights(controllers.Account, "account_view"))
	router.HandleFunc("/restore", controllers.Restore)
	router.HandleFunc("/restore/{restoretoken:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}", controllers.RestoreSetNewPassword)
	router.HandleFunc("/users", mid.RequireRights(controllers.Users, "users_list"))
	router.HandleFunc("/users/new", mid.RequireRights(controllers.UsersNew, "user_create"))
	router.HandleFunc("/users/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.UsersEdit, "user_edit"))
	
	//DNS zones
	router.HandleFunc("/zones", mid.RequireRights(controllers.Zones, "zones_view"))
	router.HandleFunc("/zone/new", mid.RequireRights(controllers.ZoneNew, "zone_create"))
	router.HandleFunc("/zone/{id:[a-zA-Z0-9]+}/hits", mid.RequireRights(controllers.Hits, "zone_view"))
	router.HandleFunc("/zones/updatednsconfig", mid.RequireRights(controllers.UpdateDNSConfig, "zones_edit"))

	//DNS rebind
	router.HandleFunc("/rebind", mid.RequireRights(controllers.Rebind, "rebind_view"))
	router.HandleFunc("/rebind/new", mid.RequireRights(controllers.RebindNew, "rebind_create"))
	router.HandleFunc("/rebind/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.RebindEdit, "rebind_edit"))

	//DNS blackhole
	router.HandleFunc("/blackhole", mid.RequireRights(controllers.BlackHole, "blackhole_view"))
	router.HandleFunc("/blackhole/new", mid.RequireRights(controllers.BlackHoleNew, "blackhole_create"))
	router.HandleFunc("/blackhole/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.BlackHoleEdit, "blackhole_edit"))

	//DNS records
	router.HandleFunc("/records", mid.RequireRights(controllers.Records, "records_view"))
	router.HandleFunc("/records/new", mid.RequireRights(controllers.RecordsNew, "record_create"))
	router.HandleFunc("/records/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.RecordsEdit, "record_edit"))

	//Interact block
	router.HandleFunc("/interacts", mid.RequireRights(controllers.Interacts, "interacts_view"))
	router.HandleFunc("/interact/share", mid.RequireRights(controllers.InteractShare, "interacts_share"))
	router.HandleFunc("/interact/new", mid.RequireRights(controllers.InteractNew, "interact_create"))
	router.HandleFunc("/interact/{id:[0-9a-z]{24}}/hits", mid.RequireRights(controllers.InteractHits, "interact_view"))
	router.HandleFunc("/interact/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.InteractEdit, "interact_edit"))
	router.HandleFunc("/interact/updateconfig", mid.RequireRights(controllers.UpdateInteractConfig, "interact_edit_config"))

	//XSShunter block
	router.HandleFunc("/xsshunter", mid.RequireRights(controllers.XssHunter, "xsshunters_view"))
	router.HandleFunc("/xsshunter/new", mid.RequireRights(controllers.XssHunterNew, "xsshunter_create"))
	router.HandleFunc("/xsshunter/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/hits", mid.RequireRights(controllers.XssHunterHits, "xsshunter_view"))
	router.HandleFunc("/xsshunter/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/settings", mid.RequireRights(controllers.XssHunterSettings, "xsshunter_edit"))
	router.HandleFunc("/xsshunter/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/payloads", mid.RequireRights(controllers.XssHunterPayloads, "xsshunter_payload_view"))
	router.HandleFunc("/xsshunter/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/payloads/new", mid.RequireRights(controllers.XssHunterNewPayloads, "xsshunter_payload_create"))
	router.HandleFunc("/h/{name:[a-zA-Z0-9-]+}", mid.SetMaxSize(mid.Use(controllers.XssHunterServePayload), 50))

	//Misc admin funcs
	router.HandleFunc("/certs", mid.RequireRights(controllers.CertsInfo, "certs"))
	router.HandleFunc("/cert/new", mid.RequireRights(controllers.CertNew, "certs"))
	router.HandleFunc("/logs", mid.RequireRights(controllers.Logs, "logs"))

	//API block
	api := new_api_handler()
	router.PathPrefix("/api/").Handler(api)

	//Static router
	router.PathPrefix("/").Handler(http.FileServer(utils.Dir("./static")))

	//Apply middlewares
	//Check client ip if whitelist configured 
	handler := mid.Use(router.ServeHTTP, mid.CheckIP)
	//Load session context
	handler = mid.Use(handler, mid.GetContext)
	//Apply security headers to answer
	handler = mid.Use(handler, mid.ApplySecHeaders)

	return handler
}