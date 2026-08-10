package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"secaudit/internal/api"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "persistent storage directory")
	flag.Parse()

	store := api.NewStore(*dataDir)
	apiKeyGuard := api.NewAPIKeyGuard()
	rateLimiter := api.NewRateLimiter(30, time.Minute)

	api.StartScheduler(store)

	mux := http.NewServeMux()

	protect := func(h http.HandlerFunc) http.HandlerFunc {
		return api.CORSMiddleware(rateLimiter.Middleware(apiKeyGuard.Middleware(h)))
	}

	mux.HandleFunc("/", api.DashboardHandler)
	mux.HandleFunc("/api/scan", protect(api.ScanHandler(store)))
	mux.HandleFunc("/api/report/", protect(api.ReportHandler(store)))
	mux.HandleFunc("/api/history/", protect(api.HistoryHandler(store)))
	mux.HandleFunc("/api/diff/", protect(api.DiffHandler(store)))
	mux.HandleFunc("/api/recurring", protect(api.RecurringCreateHandler(store)))
	mux.HandleFunc("/api/recurring/list", protect(api.RecurringListHandler(store)))
	mux.HandleFunc("/api/recurring/delete/", protect(api.RecurringDeleteHandler(store)))
	mux.HandleFunc("/api/report-html/", protect(api.HTMLReportHandler(store)))

	if apiKeyGuard.Enabled() {
		fmt.Fprintln(os.Stderr, "API anahtari korumasi aktif")
	} else {
		fmt.Fprintln(os.Stderr, "UYARI: SECAUDIT_API_KEYS tanimli degil, API anahtari korumasi pasif")
	}

	fmt.Fprintf(os.Stderr, "SecAudit API starting on %s\n", *addr)
	fmt.Fprintf(os.Stderr, "Dashboard: http://localhost%s\n", *addr)
	fmt.Fprintf(os.Stderr, "Data directory: %s\n", *dataDir)

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
