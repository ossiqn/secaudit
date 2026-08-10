package scanner

import (
	"sync"
	"time"
)

type FullReport struct {
	Domain         string              `json:"domain"`
	TLS            *TLSResult          `json:"tls,omitempty"`
	Headers        *HeaderResult       `json:"headers,omitempty"`
	Email          *EmailSecResult     `json:"email,omitempty"`
	Exposed        *ExposedResult      `json:"exposed,omitempty"`
	Cookies        *CookieResult       `json:"cookies,omitempty"`
	CORS           *CORSResult         `json:"cors,omitempty"`
	Subdomains     *SubdomainResult    `json:"subdomains,omitempty"`
	Ports          *PortScanResult     `json:"ports,omitempty"`
	MixedContent   *MixedContentResult `json:"mixed_content,omitempty"`
	Clickjacking   *ClickjackingResult `json:"clickjacking,omitempty"`
	Whois          *WhoisResult        `json:"whois,omitempty"`
	Reputation     *ReputationResult   `json:"reputation,omitempty"`
	Score          *ScoreResult        `json:"score,omitempty"`
	Blocked        bool                `json:"blocked,omitempty"`
	BlockReason    string              `json:"block_reason,omitempty"`
	PartialTimeout bool                `json:"partial_timeout,omitempty"`
}

const scanOverallDeadline = 45 * time.Second

func RunFullScan(domain string) (*FullReport, error) {
	report := &FullReport{Domain: domain}

	check := ValidateDomainSafe(domain)
	if !check.Safe {
		report.Blocked = true
		report.BlockReason = check.Reason
		return report, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	var tlsR *TLSResult
	var headersR *HeaderResult
	var emailR *EmailSecResult
	var exposedR *ExposedResult
	var cookiesR *CookieResult
	var corsR *CORSResult
	var subdomainsR *SubdomainResult
	var portsR *PortScanResult
	var mixedR *MixedContentResult
	var clickjackR *ClickjackingResult
	var whoisR *WhoisResult
	var reputationR *ReputationResult

	runParallel := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	runParallel(func() { r := CheckTLS(domain); mu.Lock(); tlsR = r; mu.Unlock() })
	runParallel(func() { r := CheckHeaders(domain); mu.Lock(); headersR = r; mu.Unlock() })
	runParallel(func() { r := CheckEmailSec(domain); mu.Lock(); emailR = r; mu.Unlock() })
	runParallel(func() { r := CheckExposed(domain); mu.Lock(); exposedR = r; mu.Unlock() })
	runParallel(func() { r := CheckCookies(domain); mu.Lock(); cookiesR = r; mu.Unlock() })
	runParallel(func() { r := CheckCORS(domain); mu.Lock(); corsR = r; mu.Unlock() })
	runParallel(func() { r := EnumerateSubdomains(domain); mu.Lock(); subdomainsR = r; mu.Unlock() })
	runParallel(func() { r := ScanCommonPorts(domain); mu.Lock(); portsR = r; mu.Unlock() })
	runParallel(func() { r := CheckMixedContent(domain); mu.Lock(); mixedR = r; mu.Unlock() })
	runParallel(func() { r := CheckClickjacking(domain); mu.Lock(); clickjackR = r; mu.Unlock() })
	runParallel(func() { r := CheckWhois(domain); mu.Lock(); whoisR = r; mu.Unlock() })
	runParallel(func() { r := CheckReputation(domain); mu.Lock(); reputationR = r; mu.Unlock() })

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(scanOverallDeadline):
		report.PartialTimeout = true
	}

	mu.Lock()
	report.TLS = tlsR
	report.Headers = headersR
	report.Email = emailR
	report.Exposed = exposedR
	report.Cookies = cookiesR
	report.CORS = corsR
	report.Subdomains = subdomainsR
	report.Ports = portsR
	report.MixedContent = mixedR
	report.Clickjacking = clickjackR
	report.Whois = whoisR
	report.Reputation = reputationR
	mu.Unlock()

	report.Score = CalculateScore(report)

	return report, nil
}
