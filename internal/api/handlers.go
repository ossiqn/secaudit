package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"secaudit/internal/scanner"
)

func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func ScanHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
		req.Domain = strings.TrimPrefix(req.Domain, "http://")
		req.Domain = strings.TrimPrefix(req.Domain, "https://")
		req.Domain = strings.TrimSuffix(req.Domain, "/")
		if req.Domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain required"})
			return
		}
		job := store.CreateJob(req.Domain)
		go func() {
			store.UpdateJob(job.ID, "running", nil, "")
			report, err := scanner.RunFullScan(req.Domain)
			if err != nil {
				store.UpdateJob(job.ID, "error", nil, err.Error())
				return
			}
			store.UpdateJob(job.ID, "done", report, "")
		}()
		writeJSON(w, 202, map[string]interface{}{
			"job_id": job.ID,
			"status": "queued",
		})
	}
}

func ReportHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/report/")
		if id == "" {
			writeJSON(w, 400, map[string]string{"error": "job id required"})
			return
		}
		job := store.GetJob(id)
		if job == nil {
			writeJSON(w, 404, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, 200, job)
	}
}

func HistoryHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := strings.TrimPrefix(r.URL.Path, "/api/history/")
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain required"})
			return
		}
		jobs := store.GetHistory(domain)
		writeJSON(w, 200, map[string]interface{}{
			"domain": domain,
			"scans":  jobs,
		})
	}
}