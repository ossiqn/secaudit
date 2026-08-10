package scanner

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type ClickjackingResult struct {
	Reachable      bool     `json:"reachable"`
	Protected      bool     `json:"protected"`
	XFrameOptions  string   `json:"x_frame_options"`
	FrameAncestors string   `json:"frame_ancestors"`
	Warnings       []string `json:"warnings,omitempty"`
}

func CheckClickjacking(domain string) *ClickjackingResult {
	result := &ClickjackingResult{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		resp, err = client.Get("http://" + domain)
		if err != nil {
			result.Warnings = append(result.Warnings, "baglanti kurulamadi: "+err.Error())
			return result
		}
	}
	defer resp.Body.Close()
	result.Reachable = true

	xfo := resp.Header.Get("X-Frame-Options")
	result.XFrameOptions = xfo

	csp := resp.Header.Get("Content-Security-Policy")
	lowerCSP := strings.ToLower(csp)
	if idx := strings.Index(lowerCSP, "frame-ancestors"); idx != -1 {
		rest := csp[idx:]
		if semi := strings.Index(rest, ";"); semi != -1 {
			result.FrameAncestors = strings.TrimSpace(rest[:semi])
		} else {
			result.FrameAncestors = strings.TrimSpace(rest)
		}
	}

	xfoUpper := strings.ToUpper(strings.TrimSpace(xfo))
	hasXFO := xfoUpper == "DENY" || xfoUpper == "SAMEORIGIN" || strings.HasPrefix(xfoUpper, "ALLOW-FROM")
	hasFrameAncestors := result.FrameAncestors != ""

	result.Protected = hasXFO || hasFrameAncestors

	if !result.Protected {
		result.Warnings = append(result.Warnings, "sayfa iframe icine gomulmeye karsi korumasiz, clickjacking saldirilarina acik")
	}

	return result
}
