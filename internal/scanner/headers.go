package scanner

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type HeaderResult struct {
	HSTSPresent     bool     `json:"hsts_present"`
	HSTSValue       string   `json:"hsts_value"`
	CSPPresent      bool     `json:"csp_present"`
	CSPValue        string   `json:"csp_value"`
	XFramePresent   bool     `json:"xframe_present"`
	XFrameValue     string   `json:"xframe_value"`
	XCTOPresent     bool     `json:"xcto_present"`
	XCTOValue       string   `json:"xcto_value"`
	ReferrerPresent bool     `json:"referrer_present"`
	ReferrerValue   string   `json:"referrer_value"`
	PermPolicy      bool     `json:"permissions_policy"`
	ServerHeader    string   `json:"server_header"`
	PoweredBy       string   `json:"powered_by"`
	Warnings        []string `json:"warnings,omitempty"`
}

func CheckHeaders(domain string) *HeaderResult {
	result := &HeaderResult{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		resp, err = client.Get("http://" + domain)
		if err != nil {
			result.Warnings = append(result.Warnings, "could not connect: "+err.Error())
			return result
		}
	}
	defer resp.Body.Close()

	h := resp.Header

	hsts := h.Get("Strict-Transport-Security")
	if hsts != "" {
		result.HSTSPresent = true
		result.HSTSValue = hsts
	}

	csp := h.Get("Content-Security-Policy")
	if csp != "" {
		result.CSPPresent = true
		result.CSPValue = csp
	}

	xfo := h.Get("X-Frame-Options")
	if xfo != "" {
		result.XFramePresent = true
		result.XFrameValue = xfo
	}

	xcto := h.Get("X-Content-Type-Options")
	if xcto != "" {
		result.XCTOPresent = true
		result.XCTOValue = xcto
	}

	ref := h.Get("Referrer-Policy")
	if ref != "" {
		result.ReferrerPresent = true
		result.ReferrerValue = ref
	}

	pp := h.Get("Permissions-Policy")
	if pp != "" {
		result.PermPolicy = true
	}

	srv := h.Get("Server")
	if srv != "" {
		result.ServerHeader = srv
		lower := strings.ToLower(srv)
		if strings.Contains(lower, "apache") || strings.Contains(lower, "nginx") || strings.Contains(lower, "iis") {
			result.Warnings = append(result.Warnings, "server header leaks software info: "+srv)
		}
	}

	xpb := h.Get("X-Powered-By")
	if xpb != "" {
		result.PoweredBy = xpb
		result.Warnings = append(result.Warnings, "x-powered-by header leaks info: "+xpb)
	}

	return result
}