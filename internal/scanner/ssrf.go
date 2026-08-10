package scanner

import (
	"fmt"
	"net"
	"strings"
)

var deniedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"::ffff:0:0/96",
}

var deniedNets []*net.IPNet

func init() {
	for _, c := range deniedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			deniedNets = append(deniedNets, n)
		}
	}
}

func isDeniedIP(ip net.IP) bool {
	v4 := ip.To4()
	for _, n := range deniedNets {
		if v4 != nil && len(n.IP) == 4 {
			if n.Contains(v4) {
				return true
			}
			continue
		}
		if v4 == nil && len(n.IP) == 16 {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

type SSRFCheckResult struct {
	Safe      bool
	Reason    string
	Addresses []string
}

func ValidateDomainSafe(domain string) SSRFCheckResult {
	host := strings.TrimSpace(strings.ToLower(domain))
	host = strings.TrimSuffix(host, ".")

	if host == "" {
		return SSRFCheckResult{Safe: false, Reason: "bos domain"}
	}
	if host == "localhost" {
		return SSRFCheckResult{Safe: false, Reason: "localhost hedef olarak kabul edilmiyor"}
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDeniedIP(ip) {
			return SSRFCheckResult{Safe: false, Reason: "hedef ozel/rezerve IP araligina giriyor: " + ip.String()}
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return SSRFCheckResult{Safe: false, Reason: "dns cozumlemesi basarisiz: " + err.Error()}
	}
	if len(ips) == 0 {
		return SSRFCheckResult{Safe: false, Reason: "domain hicbir IP adresine cozumlenmedi"}
	}

	var addrs []string
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
		if isDeniedIP(ip) {
			return SSRFCheckResult{
				Safe:      false,
				Reason:    fmt.Sprintf("domain ozel/rezerve bir IP adresine cozumleniyor: %s", ip.String()),
				Addresses: addrs,
			}
		}
	}

	return SSRFCheckResult{Safe: true, Addresses: addrs}
}
