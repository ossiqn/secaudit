package scanner

import (
	"crypto/tls"
	"net/http"
	"time"
)

type ExposedFile struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type ExposedResult struct {
	FoundFiles []ExposedFile `json:"found_files"`
	Checked    int           `json:"checked"`
	Warnings   []string      `json:"warnings,omitempty"`
}

var sensitiveFiles = []string{
	"/.git/config",
	"/.git/HEAD",
	"/.env",
	"/.env.local",
	"/.env.production",
	"/wp-config.php.bak",
	"/wp-config.php~",
	"/.htpasswd",
	"/.htaccess",
	"/server-status",
	"/server-info",
	"/.DS_Store",
	"/phpinfo.php",
	"/info.php",
	"/.well-known/security.txt",
	"/robots.txt",
	"/sitemap.xml",
	"/.aws/credentials",
	"/.docker/config.json",
	"/backup.sql",
	"/dump.sql",
	"/database.sql",
	"/.svn/entries",
	"/crossdomain.xml",
	"/elmah.axd",
	"/trace.axd",
	"/config.yml",
	"/config.yaml",
	"/docker-compose.yml",
	"/.npmrc",
	"/.bash_history",
}

func CheckExposed(domain string) *ExposedResult {
	result := &ExposedResult{}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := "https://" + domain

	for _, path := range sensitiveFiles {
		result.Checked++
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			safe := false
			if path == "/robots.txt" || path == "/sitemap.xml" || path == "/.well-known/security.txt" {
				safe = true
			}
			if !safe {
				result.FoundFiles = append(result.FoundFiles, ExposedFile{
					Path:   path,
					Status: resp.StatusCode,
				})
			}
		}
	}

	return result
}