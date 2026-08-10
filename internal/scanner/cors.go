package scanner

import (
	"crypto/tls"
	"net/http"
	"time"
)

type CORSResult struct {
	Reachable          bool     `json:"reachable"`
	ReflectsOrigin     bool     `json:"reflects_origin"`
	AllowsCredentials  bool     `json:"allows_credentials"`
	AllowOriginValue   string   `json:"allow_origin_value"`
	WildcardWithCreds  bool     `json:"wildcard_with_credentials"`
	DangerousMisconfig bool     `json:"dangerous_misconfig"`
	Warnings           []string `json:"warnings,omitempty"`
}

func CheckCORS(domain string) *CORSResult {
	result := &CORSResult{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	testOrigin := "https://secaudit-cors-test.invalid"

	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		result.Warnings = append(result.Warnings, "istek olusturulamadi: "+err.Error())
		return result
	}
	req.Header.Set("Origin", testOrigin)

	resp, err := client.Do(req)
	if err != nil {
		req2, err2 := http.NewRequest("GET", "http://"+domain, nil)
		if err2 != nil {
			result.Warnings = append(result.Warnings, "baglanti kurulamadi: "+err.Error())
			return result
		}
		req2.Header.Set("Origin", testOrigin)
		resp, err = client.Do(req2)
		if err != nil {
			result.Warnings = append(result.Warnings, "baglanti kurulamadi: "+err.Error())
			return result
		}
	}
	defer resp.Body.Close()
	result.Reachable = true

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	result.AllowOriginValue = acao
	result.AllowsCredentials = acac == "true"

	if acao == testOrigin {
		result.ReflectsOrigin = true
		result.Warnings = append(result.Warnings, "server, gonderilen Origin basligini oldugu gibi yansitiyor, herhangi bir site cross-origin istek atabilir")
		if result.AllowsCredentials {
			result.DangerousMisconfig = true
			result.Warnings = append(result.Warnings, "Origin yansitiliyor ve Allow-Credentials: true, bu kimlik dogrulamali istekleri her yerden savunmasiz birakir")
		}
	}

	if acao == "*" && result.AllowsCredentials {
		result.WildcardWithCreds = true
		result.DangerousMisconfig = true
		result.Warnings = append(result.Warnings, "Access-Control-Allow-Origin: * ile Allow-Credentials: true birlikte kullanilamaz, tarayici bunu reddeder ama yanlis konfigurasyonu gosterir")
	}

	return result
}
