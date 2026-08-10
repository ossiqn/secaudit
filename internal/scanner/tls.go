package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSResult struct {
	Connected       bool     `json:"connected"`
	Protocol        string   `json:"protocol"`
	CipherSuite     string   `json:"cipher_suite"`
	CertValid       bool     `json:"cert_valid"`
	Issuer          string   `json:"issuer"`
	Subject         string   `json:"subject"`
	SANs            []string `json:"sans"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	ChainLength     int      `json:"chain_length"`
	WeakCiphers     []string `json:"weak_ciphers,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

var weakCipherList = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

func CheckTLS(domain string) *TLSResult {
	result := &TLSResult{}
	addr := domain + ":443"

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         domain,
	})
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			conn2, err2 := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         domain,
			})
			if err2 == nil {
				defer conn2.Close()
				state := conn2.ConnectionState()
				result.Connected = true
				result.CertValid = false
				result.Protocol = tlsVersionString(state.Version)
				result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
				result.Warnings = append(result.Warnings, "certificate validation failed: "+err.Error())
				if len(state.PeerCertificates) > 0 {
					cert := state.PeerCertificates[0]
					result.Issuer = cert.Issuer.String()
					result.Subject = cert.Subject.String()
					result.SANs = cert.DNSNames
					result.NotBefore = cert.NotBefore.Format(time.RFC3339)
					result.NotAfter = cert.NotAfter.Format(time.RFC3339)
					result.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
					result.ChainLength = len(state.PeerCertificates)
				}
				return result
			}
		}
		result.Connected = false
		result.Warnings = append(result.Warnings, "connection failed: "+err.Error())
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.Connected = true
	result.CertValid = true
	result.Protocol = tlsVersionString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Issuer = cert.Issuer.String()
		result.Subject = cert.Subject.String()
		result.SANs = cert.DNSNames
		result.NotBefore = cert.NotBefore.Format(time.RFC3339)
		result.NotAfter = cert.NotAfter.Format(time.RFC3339)
		result.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		result.ChainLength = len(state.PeerCertificates)
	}

	if state.Version < tls.VersionTLS12 {
		result.Warnings = append(result.Warnings, "outdated TLS version: "+result.Protocol)
	}

	for _, wc := range weakCipherList {
		if state.CipherSuite == wc {
			result.WeakCiphers = append(result.WeakCiphers, tls.CipherSuiteName(wc))
		}
	}

	return result
}
