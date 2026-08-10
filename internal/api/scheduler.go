package api

import (
	"fmt"
	"os"
	"time"

	"secaudit/internal/scanner"
)

func StartScheduler(store *Store) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			due := store.DueRecurring()
			for _, rs := range due {
				domain := rs.Domain
				store.MarkRecurringRun(domain)

				go func(domain string) {
					scanSemaphore <- struct{}{}
					defer func() { <-scanSemaphore }()

					job := store.CreateJob(domain)
					store.UpdateJob(job.ID, "running", nil, "")
					report, err := scanner.RunFullScan(domain)
					if err != nil {
						store.UpdateJob(job.ID, "error", nil, err.Error())
						fmt.Fprintf(os.Stderr, "periyodik tarama hatasi (%s): %v\n", domain, err)
						return
					}
					store.UpdateJob(job.ID, "done", report, "")
				}(domain)
			}
		}
	}()
}
