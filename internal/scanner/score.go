package scanner

type ScoreResult struct {
	TotalScore      int      `json:"total_score"`
	Grade           string   `json:"grade"`
	TLSScore        int      `json:"tls_score"`
	HeaderScore     int      `json:"header_score"`
	EmailScore      int      `json:"email_score"`
	ExposedScore    int      `json:"exposed_score"`
	Recommendations []string `json:"recommendations"`
}

func CalculateScore(tlsR *TLSResult, headersR *HeaderResult, emailR *EmailSecResult, exposedR *ExposedResult) *ScoreResult {
	s := &ScoreResult{}

	if tlsR != nil && tlsR.Connected {
		s.TLSScore += 10
		if tlsR.CertValid {
			s.TLSScore += 10
		} else {
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi gecersiz, yenileyin")
		}
		if tlsR.DaysUntilExpiry > 30 {
			s.TLSScore += 10
		} else if tlsR.DaysUntilExpiry > 7 {
			s.TLSScore += 5
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi yakinda sona erecek")
		} else {
			s.Recommendations = append(s.Recommendations, "SSL sertifikasi acil yenilenmeli")
		}
	} else {
		s.Recommendations = append(s.Recommendations, "HTTPS aktif degil, SSL sertifikasi kurun")
	}

	if headersR != nil {
		if headersR.HSTSPresent {
			s.HeaderScore += 10
		} else {
			s.Recommendations = append(s.Recommendations, "HSTS header ekleyin")
		}
		if headersR.CSPPresent {
			s.HeaderScore += 10
		} else {
			s.Recommendations = append(s.Recommendations, "Content-Security-Policy header ekleyin")
		}
		if headersR.XFramePresent {
			s.HeaderScore += 5
		} else {
			s.Recommendations = append(s.Recommendations, "X-Frame-Options header ekleyin")
		}
		if headersR.XCTOPresent {
			s.HeaderScore += 5
		} else {
			s.Recommendations = append(s.Recommendations, "X-Content-Type-Options: nosniff ekleyin")
		}
		if headersR.ReferrerPresent {
			s.HeaderScore += 5
		}
		if headersR.ServerHeader != "" {
			s.HeaderScore -= 3
			s.Recommendations = append(s.Recommendations, "Server header sunucu bilgisi sizdiriyor, kaldirin")
		}
	}

	if emailR != nil {
		if emailR.SPFFound {
			s.EmailScore += 7
		} else {
			s.Recommendations = append(s.Recommendations, "SPF kaydi ekleyin")
		}
		if emailR.DMARCFound {
			s.EmailScore += 7
		} else {
			s.Recommendations = append(s.Recommendations, "DMARC kaydi ekleyin")
		}
		if emailR.DKIMFound {
			s.EmailScore += 3
		}
		if emailR.DNSSECEnabled {
			s.EmailScore += 3
		}
	}

	if exposedR != nil {
		if len(exposedR.FoundFiles) == 0 {
			s.ExposedScore = 15
		} else {
			penalty := len(exposedR.FoundFiles) * 5
			s.ExposedScore = 15 - penalty
			if s.ExposedScore < 0 {
				s.ExposedScore = 0
			}
			s.Recommendations = append(s.Recommendations, "Acikta kalan hassas dosyalar tespit edildi, erisimi engelleyin")
		}
	}

	s.TotalScore = s.TLSScore + s.HeaderScore + s.EmailScore + s.ExposedScore
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