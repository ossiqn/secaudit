package scanner

type ScoreResult struct {
	TotalScore        int      `json:"total_score"`
	Grade             string   `json:"grade"`
	TLSScore          int      `json:"tls_score"`
	HeaderScore       int      `json:"header_score"`
	EmailScore        int      `json:"email_score"`
	ExposedScore      int      `json:"exposed_score"`
	CookieScore       int      `json:"cookie_score"`
	CORSScore         int      `json:"cors_score"`
	PortScore         int      `json:"port_score"`
	MixedContentScore int      `json:"mixed_content_score"`
	ClickjackingScore int      `json:"clickjacking_score"`
	ReputationScore   int      `json:"reputation_score"`
	Recommendations   []string `json:"recommendations"`
}

func CalculateScore(report *FullReport) *ScoreResult {
	s := &ScoreResult{}

	tlsR := report.TLS
	headersR := report.Headers
	emailR := report.Email
	exposedR := report.Exposed
	cookiesR := report.Cookies
	corsR := report.CORS
	portsR := report.Ports
	mixedR := report.MixedContent
	clickjackR := report.Clickjacking
	reputationR := report.Reputation

	if tlsR != nil && tlsR.Connected {
		s.TLSScore += 8
		if tlsR.CertValid {
			s.TLSScore += 8
		} else {
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi gecersiz, yenileyin")
		}
		if tlsR.DaysUntilExpiry > 30 {
			s.TLSScore += 8
		} else if tlsR.DaysUntilExpiry > 7 {
			s.TLSScore += 4
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi yakinda sona erecek")
		} else {
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi acil yenilenmeli")
		}
		if len(tlsR.WeakCiphers) > 0 {
			s.Recommendations = append(s.Recommendations, "zayif sifreleme paketleri devre disi birakilmali")
		} else {
			s.TLSScore += 2
		}
	} else {
		s.Recommendations = append(s.Recommendations, "HTTPS aktif degil, SSL sertifikasi kurun")
	}

	if headersR != nil {
		if headersR.HSTSPresent {
			s.HeaderScore += 8
		} else {
			s.Recommendations = append(s.Recommendations, "HSTS header ekleyin")
		}
		if headersR.CSPPresent {
			s.HeaderScore += 8
		} else {
			s.Recommendations = append(s.Recommendations, "Content-Security-Policy header ekleyin")
		}
		if headersR.XFramePresent {
			s.HeaderScore += 4
		} else {
			s.Recommendations = append(s.Recommendations, "X-Frame-Options header ekleyin")
		}
		if headersR.XCTOPresent {
			s.HeaderScore += 4
		} else {
			s.Recommendations = append(s.Recommendations, "X-Content-Type-Options: nosniff ekleyin")
		}
		if headersR.ReferrerPresent {
			s.HeaderScore += 3
		}
		if headersR.PermPolicy {
			s.HeaderScore += 3
		}
		if headersR.ServerHeader != "" {
			s.HeaderScore -= 2
			s.Recommendations = append(s.Recommendations, "Server header sunucu bilgisi sizdiriyor, kaldirin")
		}
		if headersR.PoweredBy != "" {
			s.HeaderScore -= 2
		}
	}

	if emailR != nil {
		if emailR.SPFFound {
			s.EmailScore += 5
		} else {
			s.Recommendations = append(s.Recommendations, "SPF kaydi ekleyin")
		}
		if emailR.DMARCFound {
			s.EmailScore += 5
		} else {
			s.Recommendations = append(s.Recommendations, "DMARC kaydi ekleyin")
		}
		if emailR.DKIMFound {
			s.EmailScore += 2
		}
		if emailR.DNSSECEnabled {
			s.EmailScore += 3
		} else {
			s.Recommendations = append(s.Recommendations, "DNSSEC aktif edilmesi tavsiye edilir")
		}
	}

	if exposedR != nil {
		if len(exposedR.FoundFiles) == 0 {
			s.ExposedScore = 10
		} else {
			penalty := len(exposedR.FoundFiles) * 4
			s.ExposedScore = 10 - penalty
			if s.ExposedScore < 0 {
				s.ExposedScore = 0
			}
			s.Recommendations = append(s.Recommendations, "Acikta kalan hassas dosyalar tespit edildi, erisimi engelleyin")
		}
	}

	if cookiesR != nil && cookiesR.Reachable {
		if len(cookiesR.Cookies) == 0 {
			s.CookieScore = 5
		} else {
			problematic := 0
			for _, c := range cookiesR.Cookies {
				if len(c.Issues) > 0 {
					problematic++
				}
			}
			if problematic == 0 {
				s.CookieScore = 5
			} else {
				s.CookieScore = 5 - problematic*2
				if s.CookieScore < 0 {
					s.CookieScore = 0
				}
				s.Recommendations = append(s.Recommendations, "cookie'lere Secure, HttpOnly ve SameSite ozniteliklerini ekleyin")
			}
		}
	}

	if corsR != nil && corsR.Reachable {
		if corsR.DangerousMisconfig {
			s.CORSScore = 0
			s.Recommendations = append(s.Recommendations, "CORS konfigurasyonu tehlikeli, Origin yansitma ve Allow-Credentials birlikte kullanilmamali")
		} else if corsR.ReflectsOrigin {
			s.CORSScore = 2
			s.Recommendations = append(s.Recommendations, "CORS politikasi tum originleri yansitiyor, gerekli originlerle sinirlandirin")
		} else {
			s.CORSScore = 5
		}
	}

	if portsR != nil && !portsR.Skipped {
		riskyOpen := 0
		for _, p := range portsR.OpenPorts {
			switch p.Port {
			case 3306, 5432, 6379, 27017, 9200, 11211, 3389, 5900, 2375, 2376, 23, 21:
				riskyOpen++
			}
		}
		if riskyOpen == 0 {
			s.PortScore = 5
		} else {
			s.PortScore = 5 - riskyOpen*2
			if s.PortScore < 0 {
				s.PortScore = 0
			}
			s.Recommendations = append(s.Recommendations, "internete acik olmamasi gereken servis portlari tespit edildi, guvenlik duvari ile kapatin")
		}
	}

	if mixedR != nil && mixedR.Reachable {
		if len(mixedR.InsecureRefs) == 0 {
			s.MixedContentScore = 3
		} else {
			s.MixedContentScore = 0
			s.Recommendations = append(s.Recommendations, "https sayfada http uzerinden yuklenen karisik icerik var, tum kaynaklari https yapin")
		}
	}

	if clickjackR != nil && clickjackR.Reachable {
		if clickjackR.Protected {
			s.ClickjackingScore = 3
		} else {
			s.ClickjackingScore = 0
			s.Recommendations = append(s.Recommendations, "clickjacking korumasi icin X-Frame-Options veya CSP frame-ancestors ekleyin")
		}
	}

	if reputationR != nil {
		if len(reputationR.DNSBLHits) == 0 {
			s.ReputationScore = 4
		} else {
			s.ReputationScore = 0
			s.Recommendations = append(s.Recommendations, "sunucu IP adresi bir veya daha fazla kara listede bulundu, itibar temizligi yapin")
		}
		if reputationR.SafeBrowsing == "tehdit tespit edildi" {
			s.ReputationScore = 0
			s.Recommendations = append(s.Recommendations, "Google Safe Browsing bu domain icin tehdit bildirdi, acilen inceleyin")
		}
	}

	s.TotalScore = s.TLSScore + s.HeaderScore + s.EmailScore + s.ExposedScore +
		s.CookieScore + s.CORSScore + s.PortScore + s.MixedContentScore +
		s.ClickjackingScore + s.ReputationScore

	if s.TotalScore < 0 {
		s.TotalScore = 0
	}
	if s.TotalScore > 100 {
		s.TotalScore = 100
	}

	switch {
	case s.TotalScore >= 90:
		s.Grade = "A+"
	case s.TotalScore >= 80:
		s.Grade = "A"
	case s.TotalScore >= 70:
		s.Grade = "B"
	case s.TotalScore >= 60:
		s.Grade = "C"
	case s.TotalScore >= 40:
		s.Grade = "D"
	default:
		s.Grade = "F"
	}

	return s
}
