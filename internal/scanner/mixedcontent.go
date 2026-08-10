package scanner

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"time"
)

type MixedContentResult struct {
	Reachable    bool     `json:"reachable"`
	HTTPSWorks   bool     `json:"https_works"`
	InsecureRefs []string `json:"insecure_refs,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

var mixedContentPattern = regexp.MustCompile(`(?i)(?:src|href)=["']http://[^"']+["']`)

func CheckMixedContent(domain string) *MixedContentResult {
	result := &MixedContentResult{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		result.Warnings = append(result.Warnings, "https uzerinden baglanti kurulamadi: "+err.Error())
		return result
	}
	defer resp.Body.Close()
	result.Reachable = true
	result.HTTPSWorks = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		result.Warnings = append(result.Warnings, "sayfa icerigi okunamadi: "+err.Error())
		return result
	}

	matches := mixedContentPattern.FindAll(body, -1)
	seen := map[string]bool{}
	for _, m := range matches {
		s := string(m)
		if !seen[s] {
			seen[s] = true
			result.InsecureRefs = append(result.InsecureRefs, s)
		}
		if len(result.InsecureRefs) >= 20 {
			break
		}
	}

	if len(result.InsecureRefs) > 0 {
		result.Warnings = append(result.Warnings, "https sayfada http uzerinden yuklenen kaynaklar bulundu")
	}

	return result
}
