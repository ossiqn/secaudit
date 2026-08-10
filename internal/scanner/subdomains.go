package scanner

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

var commonSubdomains = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
	"cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile", "admin",
	"api", "dev", "staging", "test", "beta", "demo", "portal", "vpn",
	"remote", "cdn", "static", "assets", "img", "images", "media", "blog",
	"shop", "store", "app", "apps", "dashboard", "panel", "secure", "login",
	"support", "help", "docs", "status", "monitor", "grafana", "kibana",
	"jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki",
	"db", "database", "mysql", "postgres", "redis", "cache", "s3", "backup",
	"old", "new", "beta2", "internal", "intranet", "extranet", "partner",
	"partners", "crm", "erp", "hr", "payroll", "billing", "pay", "payment",
	"webdisk", "ns3", "ns4", "mx", "mx1", "mx2", "email", "server",
}

type SubdomainFinding struct {
	Subdomain string   `json:"subdomain"`
	Addresses []string `json:"addresses"`
}

type SubdomainResult struct {
	Checked int                `json:"checked"`
	Found   []SubdomainFinding `json:"found"`
}

func EnumerateSubdomains(domain string) *SubdomainResult {
	result := &SubdomainResult{Checked: len(commonSubdomains)}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := sub + "." + domain
			resolver := &net.Resolver{}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			result.Found = append(result.Found, SubdomainFinding{
				Subdomain: fqdn,
				Addresses: ips,
			})
			mu.Unlock()
		}(sub)
	}

	wg.Wait()

	sort.Slice(result.Found, func(i, j int) bool {
		return result.Found[i].Subdomain < result.Found[j].Subdomain
	})

	return result
}
