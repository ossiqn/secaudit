package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	110:   "POP3",
	111:   "RPCBind",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	445:   "SMB",
	1433:  "MSSQL",
	1521:  "Oracle",
	2049:  "NFS",
	2375:  "Docker",
	2376:  "Docker-TLS",
	3000:  "Dev-Server",
	3306:  "MySQL",
	3389:  "RDP",
	5000:  "Dev-Server",
	5432:  "PostgreSQL",
	5601:  "Kibana",
	5672:  "RabbitMQ",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9000:  "HTTP-Alt",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch",
	11211: "Memcached",
	15672: "RabbitMQ-Mgmt",
	27017: "MongoDB",
	28017: "MongoDB-HTTP",
}

type OpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

type PortScanResult struct {
	Target     string     `json:"target"`
	Checked    int        `json:"checked"`
	OpenPorts  []OpenPort `json:"open_ports"`
	Skipped    bool       `json:"skipped"`
	SkipReason string     `json:"skip_reason,omitempty"`
}

func ScanCommonPorts(domain string) *PortScanResult {
	result := &PortScanResult{Checked: len(commonPorts)}

	check := ValidateDomainSafe(domain)
	if !check.Safe {
		result.Skipped = true
		result.SkipReason = check.Reason
		return result
	}
	if len(check.Addresses) == 0 {
		result.Skipped = true
		result.SkipReason = "hedef IP adresi bulunamadi"
		return result
	}

	target := check.Addresses[0]
	result.Target = target

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for port, name := range commonPorts {
		wg.Add(1)
		go func(port int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			result.OpenPorts = append(result.OpenPorts, OpenPort{Port: port, Service: name})
			mu.Unlock()
		}(port, name)
	}

	wg.Wait()

	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Port < result.OpenPorts[j].Port
	})

	return result
}
