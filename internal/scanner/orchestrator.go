package scanner

import (
	"sync"
)

type FullReport struct {
	Domain  string          `json:"domain"`
	TLS     *TLSResult      `json:"tls,omitempty"`
	Headers *HeaderResult   `json:"headers,omitempty"`
	Email   *EmailSecResult `json:"email,omitempty"`
	Exposed *ExposedResult  `json:"exposed,omitempty"`
	Score   *ScoreResult    `json:"score,omitempty"`
}

func RunFullScan(domain string) (*FullReport, error) {
	report := &FullReport{Domain: domain}
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := CheckTLS(domain)
		mu.Lock()
		report.TLS = r
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := CheckHeaders(domain)
		mu.Lock()
		report.Headers = r
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := CheckEmailSec(domain)
		mu.Lock()
		report.Email = r
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r := CheckExposed(domain)
		mu.Lock()
		report.Exposed = r
		mu.Unlock()
	}()

	wg.Wait()

	report.Score = CalculateScore(report.TLS, report.Headers, report.Email, report.Exposed)

	return report, nil
}