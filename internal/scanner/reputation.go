package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type BlacklistHit struct {
	Provider string `json:"provider"`
	Address  string `json:"address"`
	Result   string `json:"result"`
}

type ReputationResult struct {
	Addresses    []string       `json:"addresses"`
	DNSBLChecked bool           `json:"dnsbl_checked"`
	DNSBLHits    []BlacklistHit `json:"dnsbl_hits,omitempty"`
	SafeBrowsing string         `json:"safe_browsing"`
	Warnings     []string       `json:"warnings,omitempty"`
}

var dnsblZones = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
}

func reverseIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
}

func checkDNSBL(ip net.IP) []BlacklistHit {
	var hits []BlacklistHit
	rev := reverseIPv4(ip)
	if rev == "" {
		return hits
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	resolver := &net.Resolver{}

	for _, zone := range dnsblZones {
		wg.Add(1)
		go func(zone string) {
			defer wg.Done()
			query := rev + "." + zone
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, query)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				hits = append(hits, BlacklistHit{
					Provider: zone,
					Address:  ip.String(),
					Result:   strings.Join(addrs, ", "),
				})
				mu.Unlock()
			}
		}(zone)
	}

	wg.Wait()
	return hits
}

func checkSafeBrowsing(domain string) string {
	apiKey := os.Getenv("SECAUDIT_SAFEBROWSING_KEY")
	if apiKey == "" {
		return "kontrol edilmedi (SECAUDIT_SAFEBROWSING_KEY tanimli degil)"
	}

	reqBody := map[string]interface{}{
		"client": map[string]string{
			"clientId":      "secaudit",
			"clientVersion": "1.0.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries": []map[string]string{
				{"url": "https://" + domain},
				{"url": "http://" + domain},
			},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "sorgu olusturulamadi"
	}

	url := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return "sorgu basarisiz: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Sprintf("api hata kodu dondurdu: %d", resp.StatusCode)
	}

	var result struct {
		Matches []interface{} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "yanit ayristirilamadi"
	}

	if len(result.Matches) > 0 {
		return "tehdit tespit edildi"
	}
	return "temiz"
}

func CheckReputation(domain string) *ReputationResult {
	result := &ReputationResult{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		result.Warnings = append(result.Warnings, "ip cozumlemesi basarisiz: "+err.Error())
		return result
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		result.Addresses = append(result.Addresses, ip.String())
		if ip.To4() == nil {
			continue
		}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			hits := checkDNSBL(ip)
			mu.Lock()
			result.DNSBLChecked = true
			result.DNSBLHits = append(result.DNSBLHits, hits...)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	result.SafeBrowsing = checkSafeBrowsing(domain)

	return result
}
