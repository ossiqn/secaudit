package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"secaudit/internal/rawdns"
)

type OwnershipResult struct {
	DNSVerified  bool   `json:"dns_verified"`
	HTTPVerified bool   `json:"http_verified"`
	Details      string `json:"details"`
}

func CheckOwnership(domain string, token string) *OwnershipResult {
	result := &OwnershipResult{}

	txts, err := rawdns.LookupTXT("_secaudit." + domain)
	if err == nil {
		for _, t := range txts {
			if strings.Contains(t, "secaudit-verify="+token) {
				result.DNSVerified = true
				result.Details = "dns txt record found"
				return result
			}
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := "https://" + domain + "/.well-known/secaudit-verify.txt"
	resp, err := client.Get(url)
	if err != nil {
		url = "http://" + domain + "/.well-known/secaudit-verify.txt"
		resp, err = client.Get(url)
	}

	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if strings.TrimSpace(string(body)) == token {
			result.HTTPVerified = true
			result.Details = "http file token matched"
			return result
		}
	}

	result.Details = "token not found via dns or http"
	return result
}