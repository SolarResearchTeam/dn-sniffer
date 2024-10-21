package controllers

import (
	"net/http"
	"os"
	"strconv"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	utils "github.com/SolarResearchTeam/dn-sniffer/webserver/utils"

	"github.com/gorilla/mux"
)

func Interacts(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Interacts *[]ds.Interact_server
		HitsCounts map[string]int
		User *ds.Users
	}
	servers, err := models.Database.GetAllInteract()
	if err != nil {
		utils.GetTemplate(w, r, "interacts").ExecuteTemplate(w, "base", Context{Interacts:servers,HitsCounts:map[string]int{},User:user})
		return
	}
	Counter := map[string]int{}
	for _,server := range *servers {
		Counter[server.Id.Hex()], _ = models.Database.GetCountInteractHitsById(server.Id.Hex())
	}

	utils.GetTemplate(w, r, "interacts").ExecuteTemplate(w, "base", Context{Interacts:servers,HitsCounts:Counter,User:user})
}

func InteractEdit(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type Context struct {
		Interact *ds.Interact_server
		User *ds.Users
	}
	server, err := models.Database.GetInteractById(mux.Vars(r)["id"])
	if err != nil {
		log.Error("Webserver(InteractSH)", err.Error())
		http.Redirect(w, r, "/interacts", 301)
		return
	}
	utils.GetTemplate(w, r, "interactedit").ExecuteTemplate(w, "base", Context{Interact:server,User:user})
}

func InteractNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	utils.GetTemplate(w, r, "interactnew").ExecuteTemplate(w, "base", Default_context{User:user})
}

func InteractHits(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	user := r.Context().Value("user").(*ds.Users)
	
	type Context struct {
		Page  int
		Limit int
		Query string

		Total_pages int
		TotalHits   int

		ServerId string

		Hits *[]ds.Interact_hit
		User *ds.Users
	}

	page_context := Context{ServerId: id,User:user}
	page_context.Query = r.FormValue("q")

	limit, err := strconv.Atoi(r.FormValue("limit"))
	if err == nil {
		page_context.Limit = limit
	} else {
		page_context.Limit = 100
	}

	if page_context.Query != "" {
		page_context.TotalHits, err = models.Database.GetCountInteractHitsByQuery(id, page_context.Query)

	} else {
		page_context.TotalHits, _ = models.Database.GetCountInteractHitsById(id)
	}

	page_context.Total_pages = page_context.TotalHits / page_context.Limit
	if kek2 := page_context.TotalHits % page_context.Limit; kek2 > 0 {
		page_context.Total_pages = page_context.Total_pages + 1
	}
	page, err := strconv.Atoi(r.FormValue("page"))
	if (err == nil) && (page > 1) && (page <= page_context.Total_pages) {
		page_context.Page = page
	} else {
		page_context.Page = 1
	}

	if page_context.Query != "" {
		page_context.Hits, err = models.Database.GetInteractHitsByQuery(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), id, page_context.Query)
		if err != nil {
			log.Error("Webserver(InteractSH)", err.Error())
			http.Redirect(w, r, "/interacts", 301)
			return
		}
	} else {
		page_context.Hits, err = models.Database.GetInteractHitsById(page_context.Limit, (page_context.Limit * (page_context.Page - 1)), id)
		if err != nil {
			log.Error("Webserver(InteractSH)", err.Error())
			http.Redirect(w, r, "/interacts", 301)
			return
		}
	}

	utils.GetTemplate(w, r, "interacthits").ExecuteTemplate(w, "base", page_context)

}

func InteractShare(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*ds.Users)
	type File struct {
		Name    string
		Size    int64
		LastMod string
	}
	type Context struct {
		Files []File 
		User *ds.Users
	}
	files := make([]File, 0)
	entries, err := os.ReadDir(config.Conf.Interact.TmpDir)
	if err != nil {
		log.Error("Webserver(InteractSH)", err.Error())
		http.Redirect(w, r, "/interacts", 301)
		return
	}
	for _, e := range entries {
		finfo, _ := e.Info()
		fname := finfo.Name()
		fsize := finfo.Size()
		flm := finfo.ModTime().Format("2006.01.02 15:04:01")
		files = append(files, File{Name: fname, Size: fsize, LastMod: flm})
	}

	utils.GetTemplate(w, r, "interactshare").ExecuteTemplate(w, "base", Context{Files:files,User:user})
}
