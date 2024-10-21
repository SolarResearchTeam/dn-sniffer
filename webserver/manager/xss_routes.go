package manager

import (
	"net/http"

	mid "github.com/SolarResearchTeam/dn-sniffer/webserver/middleware"
	controllers "github.com/SolarResearchTeam/dn-sniffer/webserver/controllers"
	
	"github.com/gorilla/mux"
)

func new_xss_handler() http.HandlerFunc {
	router := mux.NewRouter()
	router = router.StrictSlash(true)

	//The One, The only xsshunter route
	router.HandleFunc("/h/{name:[a-zA-Z0-9-]+}", mid.Use(controllers.XssHunterServePayload))

	//Apply Max size to 50MB (in case of large screenshots)
	handler := mid.SetMaxSize(router, 50)
	
	return handler
}