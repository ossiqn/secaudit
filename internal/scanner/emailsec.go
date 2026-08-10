package scanner

import (
	"strings"

	"secaudit/internal/rawdns"
)

type EmailSecResult struct {
	SPFFound      bool     `json:"spf_found"`
	SPFRecord     string   `json:"spf_record"`
	DMARCFound    bool     `json:"dmarc_found"`
	DMARCRecord   string   `json:"dmarc_record"`
	DKIMFound     bool     `json:"dkim_found"`
	DKIMSelector  string   `json:"dkim_selector"`
	CAAFound      bool     `json:"caa_found"`
	CAARecords    []string `json:"caa_records"`
	DNSSECEnabled bool     `json:"dnssec_enabled"`
	Warnings      []string `json:"warnings,omitempty"`
}

var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2",
	"k1", "mandrill", "everlytickey1", "s1", "s2",
	"mail", "smtp", "dkim",
}

func CheckEmailSec(domain string) *EmailSecResult {
	result := &EmailSecResult{}

	txts, err := rawdns.LookupTXT(domain)
	if err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				result.SPFFound = true
				result.SPFRecord = t
				break
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "spf lookup failed: "+err.Error())
	}

	dmarcTxts, err := rawdns.LookupTXT("_dmarc." + domain)
	if err == nil {
		for _, t := range dmarcTxts {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				result.DMARCFound = true
				result.DMARCRecord = t
				break
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "dmarc lookup failed: "+err.Error())
	}

	for _, sel := range commonDKIMSelectors {
		dkimDomain := sel + "._domainkey." + domain
		txts, err := rawdns.LookupTXT(dkimDomain)
		if err == nil && len(txts) > 0 {
			for _, t := range txts {
				if strings.Contains(strings.ToLower(t), "v=dkim1") || strings.Contains(t, "p=") {
					result.DKIMFound = true
					result.DKIMSelector = sel
					break
				}
			}
		}
		if result.DKIMFound {
			break
		}
	}

	caas, err := rawdns.LookupCAA(domain)
	if err == nil && len(caas) > 0 {
		result.CAAFound = true
		for _, c := range caas {
			result.CAARecords = append(result.CAARecords, c.Tag+"="+c.Value)
		}
	}

	hasKey, _ := rawdns.LookupDNSKEY(domain)
	hasDS, _ := rawdns.LookupDS(domain)
	if hasKey || hasDS {
		result.DNSSECEnabled = true
	}

	return result
}
