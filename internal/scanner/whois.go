package scanner

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"time"
)

const ianaWhois = "whois.iana.org:43"

type WhoisResult struct {
	Queried      bool     `json:"queried"`
	Registrar    string   `json:"registrar"`
	CreationDate string   `json:"creation_date"`
	ExpiryDate   string   `json:"expiry_date"`
	NameServers  []string `json:"name_servers,omitempty"`
	WhoisServer  string   `json:"whois_server"`
	Warnings     []string `json:"warnings,omitempty"`
}

var (
	creationPattern  = regexp.MustCompile(`(?i)(creation date|created on|created|registered on|registration date)\s*:\s*(.+)`)
	expiryPattern    = regexp.MustCompile(`(?i)(registry expiry date|expiration date|expires on|expiry date)\s*:\s*(.+)`)
	registrarPattern = regexp.MustCompile(`(?i)^registrar\s*:\s*(.+)`)
	nsPattern        = regexp.MustCompile(`(?i)^name server\s*:\s*(.+)`)
	refServerPattern = regexp.MustCompile(`(?i)^whois\s*:\s*(.+)`)
)

func whoisQuery(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 6*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	_, err = conn.Write([]byte(query + "\r\n"))
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func extractRegistrableDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func CheckWhois(domain string) *WhoisResult {
	result := &WhoisResult{}
	root := extractRegistrableDomain(domain)

	ianaResp, err := whoisQuery(ianaWhois, root)
	if err != nil {
		result.Warnings = append(result.Warnings, "iana whois sorgusu basarisiz: "+err.Error())
		return result
	}

	server := "whois.verisign-grs.com:43"
	for _, line := range strings.Split(ianaResp, "\n") {
		if m := refServerPattern.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			server = strings.TrimSpace(m[1]) + ":43"
			break
		}
	}
	result.WhoisServer = server

	resp, err := whoisQuery(server, root)
	if err != nil {
		result.Warnings = append(result.Warnings, "whois sorgusu basarisiz: "+err.Error())
		return result
	}
	result.Queried = true

	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if m := creationPattern.FindStringSubmatch(trimmed); m != nil && result.CreationDate == "" {
			result.CreationDate = strings.TrimSpace(m[2])
		}
		if m := expiryPattern.FindStringSubmatch(trimmed); m != nil && result.ExpiryDate == "" {
			result.ExpiryDate = strings.TrimSpace(m[2])
		}
		if m := registrarPattern.FindStringSubmatch(trimmed); m != nil && result.Registrar == "" {
			result.Registrar = strings.TrimSpace(m[1])
		}
		if m := nsPattern.FindStringSubmatch(trimmed); m != nil {
			ns := strings.ToLower(strings.TrimSpace(m[1]))
			found := false
			for _, existing := range result.NameServers {
				if existing == ns {
					found = true
					break
				}
			}
			if !found {
				result.NameServers = append(result.NameServers, ns)
			}
		}
	}

	if result.CreationDate == "" && result.Registrar == "" {
		result.Warnings = append(result.Warnings, "whois sunucusundan ayristirilabilir veri alinamadi")
	}

	return result
}
