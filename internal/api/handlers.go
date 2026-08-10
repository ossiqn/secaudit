package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"secaudit/internal/scanner"
)

var scanSemaphore = make(chan struct{}, 5)

func allowedOrigins() map[string]bool {
	m := make(map[string]bool)
	raw := os.Getenv("SECAUDIT_ALLOWED_ORIGINS")
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			m[o] = true
		}
	}
	return m
}

func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	origins := allowedOrigins()
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (origins[origin] || origins["*"]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
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

func normalizeDomain(raw string) string {
	d := strings.TrimSpace(strings.ToLower(raw))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 && !strings.Contains(d, "::") {
		d = d[:idx]
	}
	return d
}

func ScanHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Domain    string `json:"domain"`
			Confirmed bool   `json:"confirmed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		req.Domain = normalizeDomain(req.Domain)
		if req.Domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain or ip required"})
			return
		}

		if !req.Confirmed {
			writeJSON(w, 403, map[string]string{
				"error": "bu hedefi tarama yetkiniz oldugunu onaylamadan tarama baslatilamaz",
			})
			return
		}

		check := scanner.ValidateDomainSafe(req.Domain)
		if !check.Safe {
			writeJSON(w, 400, map[string]string{"error": "hedef taranamaz: " + check.Reason})
			return
		}

		job := store.CreateJob(req.Domain)
		go func() {
			scanSemaphore <- struct{}{}
			defer func() { <-scanSemaphore }()

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
		domain := normalizeDomain(strings.TrimPrefix(r.URL.Path, "/api/history/"))
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

func DiffHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := normalizeDomain(strings.TrimPrefix(r.URL.Path, "/api/diff/"))
		if domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain required"})
			return
		}
		last := store.GetLastCompletedJobs(domain, 2)
		if len(last) < 2 {
			writeJSON(w, 400, map[string]string{"error": "karsilastirma icin en az 2 tamamlanmis tarama gerekli"})
			return
		}

		newJob := last[0]
		oldJob := last[1]

		newReport, ok1 := newJob.Result.(*scanner.FullReport)
		oldReport, ok2 := oldJob.Result.(*scanner.FullReport)
		if !ok1 || !ok2 || newReport.Score == nil || oldReport.Score == nil {
			writeJSON(w, 500, map[string]string{"error": "rapor verisi okunamadi"})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"domain":              domain,
			"old_job_id":          oldJob.ID,
			"new_job_id":          newJob.ID,
			"old_score":           oldReport.Score.TotalScore,
			"new_score":           newReport.Score.TotalScore,
			"score_delta":         newReport.Score.TotalScore - oldReport.Score.TotalScore,
			"old_grade":           oldReport.Score.Grade,
			"new_grade":           newReport.Score.Grade,
			"new_recommendations": newReport.Score.Recommendations,
		})
	}
}

func RecurringCreateHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Domain          string `json:"domain"`
			IntervalMinutes int    `json:"interval_minutes"`
			Enabled         bool   `json:"enabled"`
			Confirmed       bool   `json:"confirmed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		req.Domain = normalizeDomain(req.Domain)
		if req.Domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain required"})
			return
		}
		if req.Enabled && !req.Confirmed {
			writeJSON(w, 403, map[string]string{"error": "periyodik tarama icin yetki onayi gerekli"})
			return
		}
		if req.IntervalMinutes < 60 {
			req.IntervalMinutes = 60
		}
		rs := store.SetRecurring(req.Domain, req.IntervalMinutes, req.Enabled)
		writeJSON(w, 200, rs)
	}
}

func RecurringListHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"recurring": store.ListRecurring(),
		})
	}
}

func RecurringDeleteHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := normalizeDomain(strings.TrimPrefix(r.URL.Path, "/api/recurring/delete/"))
		if domain == "" {
			writeJSON(w, 400, map[string]string{"error": "domain required"})
			return
		}
		store.RemoveRecurring(domain)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
