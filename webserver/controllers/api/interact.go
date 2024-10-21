package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	mngr "github.com/SolarResearchTeam/dn-sniffer/webserver/interact"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Create
func Create_interact(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	type request struct {
		Type    string `json:"server_type"`
		Port    string `json:"port"`
		Sharing string `json:"sharing"`
	}

	var req request
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	is := ds.Interact_server{Running: false}
	is.Type = req.Type
	is.ListenPort, err = strconv.Atoi(req.Port)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	is.Sharing = false
	if req.Sharing == "on" {
		is.Sharing = true
	}
	_, err = models.Database.AddInteract(&is)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Read
func Read_interacts(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error     string               `json:"error"`
		Interacts []ds.Interact_server `json:"interacts"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	interacts, err := models.Database.GetAllInteract()
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(response{Error: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(response{Interacts: *interacts})
}

// Read
func Read_interact(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error    string             `json:"error"`
		Interact ds.Interact_server `json:"interact"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	id := mux.Vars(r)["id"]
	interact, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(response{Interact: *interact})
}

// Read
func Read_interact_hits(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string `json:"error"`
		Pages int    `json:"pages"`
		Total int    `json:"total"`

		Hits []ds.Interact_hit `json:"hits"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	id := mux.Vars(r)["id"]

	type request struct {
		Query string `json:"q"`
		Limit string `json:"limit"`
		Page  string `json:"page"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	query := req.Query

	limit, err := strconv.Atoi(req.Limit)
	if (err != nil) || (limit < 1) {
		limit = 100
	}

	totalHits := 0
	if query != "" {
		totalHits, _ = models.Database.GetCountInteractHitsByQuery(id, query)
	} else {
		totalHits, _ = models.Database.GetCountInteractHitsById(id)
	}

	total_pages := totalHits / limit
	if kek2 := totalHits % limit; kek2 > 0 {
		total_pages = total_pages + 1
	}

	page, err := strconv.Atoi(req.Page)
	if (err != nil) || (page < 1) || (page > total_pages) {
		page = 1
	}

	hits := []ds.Interact_hit{}
	if query != "" {
		p_hits, err := models.Database.GetInteractHitsByQuery(limit, (limit * (page - 1)), id, query)
		if err != nil {
			log.Error("Api(InteractSH)", err.Error())
			json.NewEncoder(w).Encode(Response{Err: err.Error()})
			return
		}
		hits = *p_hits
	} else {
		p_hits, err := models.Database.GetInteractHitsById(limit, (limit * (page - 1)), id)
		if err != nil {
			log.Error("Api(InteractSH)", err.Error())
			json.NewEncoder(w).Encode(Response{Err: err.Error()})
			return
		}
		hits = *p_hits
	}

	json.NewEncoder(w).Encode(response{Hits: hits, Pages: total_pages, Total: totalHits})
}

// Update
func Update_interact(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	type request struct {
		Type    string `json:"server_type"`
		Port    string `json:"port"`
		Sharing string `json:"sharing"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	//Stop server
	id := mux.Vars(r)["id"]
	interact, err := models.Database.GetInteractById(id)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	run := interact.Running
	if run {
		mngr.StopServer(id)
	}

	is := ds.Interact_server{Running: false}
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	is.Id = objId
	is.Type = req.Type
	is.ListenPort, _ = strconv.Atoi(req.Port)
	is.Sharing = false
	if req.Sharing == "on" {
		is.Sharing = true
	}
	_, err = models.Database.EditInteract(&is)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	//Start if was active
	if run {
		mngr.StartServer(id)
	}

	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Delete
func Delete_interact(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	mngr.StopServer(id)
	_, err := models.Database.InteractClear(id)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	mngr.DelServer(id)
	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Start
func Start_interact(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	mngr.StartServer(id)
	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Stop
func Stop_interact(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	mngr.StopServer(id)
	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Clear
func Clear_interact(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := models.Database.InteractClear(id)
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/interacts"})
}

// Create
func Create_share(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		//w.WriteHeader(http.StatusBadRequest)
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	mForm := r.MultipartForm

	for k, _ := range mForm.File {
		file, fileHeader, err := r.FormFile(k)
		if err != nil {
			log.Error("API(InteractSh)", err.Error())
			json.NewEncoder(w).Encode(Response{Err: err.Error()})
			return
		}
		defer file.Close()

		localFileName := path.Clean(config.Conf.Interact.TmpDir + "/" + path.Base(path.Clean(fileHeader.Filename)))
		out, err := os.OpenFile(localFileName, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Error("API(InteractSh)", err.Error())
			json.NewEncoder(w).Encode(Response{Err: err.Error()})
			return
		}
		defer out.Close()
		_, err = io.Copy(out, file)
		if err != nil {
			log.Error("API(InteractSh)", err.Error())
			json.NewEncoder(w).Encode(Response{Err: err.Error()})
			return
		}

	}

	json.NewEncoder(w).Encode(Response{Redirect: "/interact/share"})
}

// Read
func Read_share(w http.ResponseWriter, r *http.Request) {
	type File struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		LastMod string `json:"last_mod"`
	}
	type response struct {
		Files []File `json:"files"`
	}
	files := make([]File, 0)
	entries, err := os.ReadDir(config.Conf.Interact.TmpDir)
	if err != nil {
		log.Error("Webserver(InteractSH)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	for _, e := range entries {
		finfo, _ := e.Info()
		fname := finfo.Name()
		fsize := finfo.Size()
		flm := finfo.ModTime().Format("2006.01.02 15:04:01")
		files = append(files, File{Name: fname, Size: fsize, LastMod: flm})
	}

	json.NewEncoder(w).Encode(response{Files: files})
}

// Update
func Update_share(w http.ResponseWriter, r *http.Request) {
}

// Delete
func Delete_share(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err: "Method not allowed"})
		return
	}

	type request struct {
		Filename string `json:"filename"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err: "Bad json"})
		return
	}

	fname := req.Filename
	fname = path.Base(path.Clean(fname))
	err = os.Remove(path.Clean(config.Conf.Interact.TmpDir + "/" + fname))
	if err != nil {
		log.Error("API(InteractSh)", err.Error())
		json.NewEncoder(w).Encode(Response{Err: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(Response{Redirect: "/interact/share"})
}
