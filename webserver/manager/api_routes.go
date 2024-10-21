package manager

import (
	"net/http"

	config "github.com/SolarResearchTeam/dn-sniffer/config"
	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	controllers "github.com/SolarResearchTeam/dn-sniffer/webserver/controllers/api"

	"github.com/gorilla/mux"
)

func new_api_handler() http.Handler {
	root := mux.NewRouter()
	root = root.StrictSlash(true)

	router := root.PathPrefix("/api").Subrouter()

	//Auth
	authRouter := router.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/callback", controllers.OIDCcallback)
	authRouter.HandleFunc("/login", controllers.Login)
	authRouter.HandleFunc("/restore", controllers.Restore)
	authRouter.HandleFunc("/reset", controllers.ResetPassword)
	authRouter.HandleFunc("/logout", mid.RequireRights(controllers.Logout, "none"))

	//Config
	configRouter := router.PathPrefix("/config").Subrouter()
	configRouter.HandleFunc("/", mid.RequireRights(controllers.Read_config, "zones_edit", "interact_edit_config"))
	configRouter.HandleFunc("/dns", mid.RequireRights(controllers.Update_config_dns, "zones_edit"))
	configRouter.HandleFunc("/interact", mid.RequireRights(controllers.Update_config_interact, "interact_edit_config"))

	//User actions block / crud++
	userRouter := router.PathPrefix("/users").Subrouter()
	userRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_user, "user_create"))
	userRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_users, "users_list"))
	userRouter.HandleFunc("/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.Read_user, "user_view"))
	userRouter.HandleFunc("/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.Update_user, "user_edit"))
	userRouter.HandleFunc("/{id:[0-9a-z]{24}}/delete", mid.RequireRights(controllers.Delete_user, "user_delete"))
	userRouter.HandleFunc("/current", mid.RequireRights(controllers.Current_user, "account_view"))
	userRouter.HandleFunc("/current/pass", mid.RequireRights(controllers.Current_user_pass, "account_view"))

	//DNS zone actions block / crud++
	zoneRouter := router.PathPrefix("/zone").Subrouter()
	zoneRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_zone, "zone_create"))
	zoneRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_zones, "zones_view"))
	zoneRouter.HandleFunc("/hits", mid.RequireRights(controllers.Read_zones_hits, "zone_view"))
	zoneRouter.HandleFunc("/{id:[a-zA-Z0-9]+}", mid.RequireRights(controllers.Read_zone, "zones_view"))
	zoneRouter.HandleFunc("/{id:[a-zA-Z0-9]+}/hits", mid.RequireRights(controllers.Read_zone_hits, "zone_view"))
	zoneRouter.HandleFunc("/{id:[a-zA-Z0-9]+}/clean", mid.RequireRights(controllers.Clean_zone, "zone_clean"))
	zoneRouter.HandleFunc("/{id:[a-zA-Z0-9]+}/delete", mid.RequireRights(controllers.Delete_zone, "zone_delete"))

	//DNS records actions block / crud++
	recordRouter := router.PathPrefix("/record").Subrouter()
	recordRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_record, "record_create"))
	recordRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_records, "records_view"))
	recordRouter.HandleFunc("/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.Read_record, "records_view"))
	recordRouter.HandleFunc("/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.Update_record, "record_edit"))
	recordRouter.HandleFunc("/{id:[0-9a-z]{24}}/delete", mid.RequireRights(controllers.Delete_record, "record_delete"))

	//DNS rebinds actions block / crud++
	rebindRouter := router.PathPrefix("/rebind").Subrouter()
	rebindRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_rebind, "rebind_create"))
	rebindRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_rebinds, "rebind_view"))
	rebindRouter.HandleFunc("/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.Read_rebind, "rebind_view"))
	rebindRouter.HandleFunc("/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.Update_rebind, "rebind_edit"))
	rebindRouter.HandleFunc("/{id:[0-9a-z]{24}}/delete", mid.RequireRights(controllers.Delete_rebind, "rebind_delete"))

	//DNS blackhole actions block / crud++
	blackholeRouter := router.PathPrefix("/blackhole").Subrouter()
	blackholeRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_blackholes, "blackhole_view"))
	blackholeRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_blackhole, "blackhole_create"))
	blackholeRouter.HandleFunc("/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.Read_blackhole, "blackhole_view"))
	blackholeRouter.HandleFunc("/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.Update_blackhole, "blackhole_edit"))
	blackholeRouter.HandleFunc("/{id:[0-9a-z]{24}}/delete", mid.RequireRights(controllers.Delete_blackhole, "blackhole_delete"))
	blackholeRouter.HandleFunc("/{id:[0-9a-z]{24}}/clear", mid.RequireRights(controllers.Clear_blackhole, "blackhole_clean"))

	//Interacts actions block / crud++
	interactRouter := router.PathPrefix("/interact").Subrouter()
	interactRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_interacts, "interact_view"))
	interactRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_interact, "interact_create"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}", mid.RequireRights(controllers.Read_interact, "interact_edit"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}/edit", mid.RequireRights(controllers.Update_interact, "interact_edit"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}/delete", mid.RequireRights(controllers.Delete_interact, "interact_delete"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}/start", mid.RequireRights(controllers.Start_interact, "interact_run"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}/stop", mid.RequireRights(controllers.Stop_interact, "interact_run"))
	interactRouter.HandleFunc("/{id:[0-9a-z]{24}}/clear", mid.RequireRights(controllers.Clear_interact, "interact_clean"))
	interactRouter.HandleFunc("/share/", mid.RequireRights(controllers.Read_share, "interacts_share"))
	interactRouter.HandleFunc("/share/upload", mid.RequireRights(controllers.Create_share, "interacts_share"))
	interactRouter.HandleFunc("/share/delete", mid.RequireRights(controllers.Delete_share, "interacts_share"))

	//XSShunter actions block / crud++
	hunterRouter := router.PathPrefix("/xsshunter").Subrouter()
	hunterRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_hunter, "xsshunter_create"))
	hunterRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_hunters, "xsshunters_view"))
	hunterRouter.HandleFunc("/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}", mid.RequireRights(controllers.Read_hunter, "xsshunters_view"))
	hunterRouter.HandleFunc("/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/hits", mid.RequireRights(controllers.Read_hunter_hits, "xsshunter_view"))
	hunterRouter.HandleFunc("/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/delete", mid.RequireRights(controllers.Delete_hunter, "xsshunter_delete"))
	hunterRouter.HandleFunc("/{uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/clean", mid.RequireRights(controllers.Clear_hunter, "xsshunter_clean"))
	
	//Misc admin functions block / crud++
	sslRouter := router.PathPrefix("/ssl").Subrouter()
	sslRouter.HandleFunc("/list", mid.RequireRights(controllers.Read_SSLs, "certs"))
	sslRouter.HandleFunc("/new", mid.RequireRights(controllers.Create_SSL, "certs"))
	sslRouter.HandleFunc("/reload", mid.RequireRights(controllers.Reload_SSL, "certs"))
	sslRouter.HandleFunc("/renew/{name}", mid.RequireRights(controllers.Renew_SSL, "certs"))
	sslRouter.HandleFunc("/renewer/{name}/{action}", mid.RequireRights(controllers.SetRenew_SSL, "certs"))
	sslRouter.HandleFunc("/del/{name}", mid.RequireRights(controllers.Delete_SSL, "certs"))
	sslRouter.PathPrefix("/certs/").Handler(mid.RequireRights(http.StripPrefix("/api/ssl/certs", http.FileServer(http.Dir(config.Conf.SSL.Path))).ServeHTTP, "certs"))
	logsRouter := router.PathPrefix("/logs").Subrouter()
	logsRouter.HandleFunc("/", mid.RequireRights(controllers.Read_Logs, "logs"))

	return router
}