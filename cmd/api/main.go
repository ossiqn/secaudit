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
	flag.Parse()

	store := api.NewStore()

	mux := http.NewServeMux()

	mux.HandleFunc("/", api.DashboardHandler)
	mux.HandleFunc("/api/scan", api.CORSMiddleware(api.ScanHandler(store)))
	mux.HandleFunc("/api/report/", api.CORSMiddleware(api.ReportHandler(store)))
	mux.HandleFunc("/api/history/", api.CORSMiddleware(api.HistoryHandler(store)))

	fmt.Fprintf(os.Stderr, "SecAudit API starting on %s\n", *addr)
	fmt.Fprintf(os.Stderr, "Dashboard: http://localhost%s\n", *addr)

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}