package scanner

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type CookieFinding struct {
	Name     string   `json:"name"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"http_only"`
	SameSite string   `json:"same_site"`
	Issues   []string `json:"issues,omitempty"`
}

type CookieResult struct {
	Reachable bool            `json:"reachable"`
	Cookies   []CookieFinding `json:"cookies"`
	Warnings  []string        `json:"warnings,omitempty"`
}

func CheckCookies(domain string) *CookieResult {
	result := &CookieResult{}

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
			result.Warnings = append(result.Warnings, "baglanti kurulamadi: "+err.Error())
			return result
		}
	}
	defer resp.Body.Close()
	result.Reachable = true

	for _, c := range resp.Cookies() {
		finding := CookieFinding{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}
		switch c.SameSite {
		case http.SameSiteStrictMode:
			finding.SameSite = "Strict"
		case http.SameSiteLaxMode:
			finding.SameSite = "Lax"
		case http.SameSiteNoneMode:
			finding.SameSite = "None"
		default:
			finding.SameSite = "Belirtilmemis"
		}

		lowerName := strings.ToLower(c.Name)
		looksSensitive := strings.Contains(lowerName, "session") || strings.Contains(lowerName, "auth") ||
			strings.Contains(lowerName, "token") || strings.Contains(lowerName, "sid") ||
			strings.Contains(lowerName, "login")

		if !c.Secure {
			finding.Issues = append(finding.Issues, "Secure bayragi eksik")
		}
		if !c.HttpOnly {
			finding.Issues = append(finding.Issues, "HttpOnly bayragi eksik")
		}
		if finding.SameSite == "None" && !c.Secure {
			finding.Issues = append(finding.Issues, "SameSite=None fakat Secure eksik, tarayicilar bu cookie'yi reddedebilir")
		}
		if finding.SameSite == "Belirtilmemis" {
			finding.Issues = append(finding.Issues, "SameSite ozniteligi belirtilmemis")
		}
		if looksSensitive && (!c.Secure || !c.HttpOnly) {
			finding.Issues = append(finding.Issues, "oturum/kimlik bilgisi tasiyor gibi gorunuyor ancak yeterince korunmuyor")
		}

		result.Cookies = append(result.Cookies, finding)
	}

	return result
}
