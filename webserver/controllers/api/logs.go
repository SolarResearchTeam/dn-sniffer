package api

import (
	"net/http"
	"encoding/json"
	"strconv"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

//Read
func Read_Logs(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Error string 		`json:"error"`
		Pages int 			`json:"pages"`
		Total  int 			`json:"total"`

		Logs []ds.Log		`json:"logs"`
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Response{Err:"Method not allowed",})
		return
	}

	type request struct {
		Query 	string `json:"q"`
		Limit 	string `json:"limit"`
		Page 	string `json:"page"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Err:"Bad json",})
		return
	}

	query := req.Query

	limit, err := strconv.Atoi(req.Limit)
	if (err != nil) || (limit < 1) {
		limit = 100 
	}

	totalLogs := 0
	if query != "" {
		totalLogs, _ = models.Database.GetLogCountByQuery(query)
	} else {
		totalLogs, _ = models.Database.GetLogCount()
	}

	total_pages := totalLogs / limit
	if kek2 := totalLogs % limit; kek2 > 0 {
		total_pages = total_pages + 1
	}

	page, err := strconv.Atoi(req.Page)
	if (err != nil) || (page < 1) || (page > total_pages) {
		page = 1
	}

	logs := []ds.Log{}
	if query != "" {
		p_logs, _ := models.Database.GetLogsByQuery(limit, (limit * (page - 1)), query)
		logs = *p_logs
	} else {
		p_logs, _ := models.Database.GetAllLogs(limit, (limit * (page - 1)))
		logs = *p_logs
	}

	json.NewEncoder(w).Encode(response{Logs:logs,Pages:total_pages,Total:totalLogs})
}