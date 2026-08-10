package api

import (
	"html/template"
	"net/http"
	"strings"

	"secaudit/internal/scanner"
)

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>SecAudit Raporu - {{.Domain}}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#fff;color:#1a1a1a;max-width:900px;margin:0 auto;padding:40px 24px}
h1{font-size:1.8em;margin-bottom:4px}
.sub{color:#666;margin-bottom:24px}
.score-box{display:inline-block;padding:16px 28px;border-radius:12px;background:#f2f2f2;margin-bottom:24px}
.score-box .grade{font-size:2.4em;font-weight:800}
.grade-A{color:#16a34a}.grade-B{color:#65a30d}.grade-C{color:#ca8a04}.grade-D{color:#ea580c}.grade-F{color:#dc2626}
table{width:100%;border-collapse:collapse;margin-bottom:28px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e5e5;font-size:0.92em}
th{background:#f7f7f7}
h2{font-size:1.2em;margin-top:32px;border-bottom:2px solid #eee;padding-bottom:6px}
.pass{color:#16a34a;font-weight:600}
.fail{color:#dc2626;font-weight:600}
.warn{color:#ca8a04;font-weight:600}
ul.rec li{margin-bottom:6px}
.mono{font-family:monospace;font-size:0.85em}
</style>
</head>
<body>
<h1>SecAudit Guvenlik Raporu</h1>
<div class="sub">{{.Domain}} - {{.GeneratedAt}}</div>

<div class="score-box">
<div class="grade grade-{{.GradeLetter}}">{{.Grade}}</div>
<div>{{.TotalScore}} / 100</div>
</div>

{{if .Blocked}}
<p><strong>Tarama engellendi:</strong> {{.BlockReason}}</p>
{{else}}

<h2>TLS / SSL</h2>
<table>
<tr><th>Alan</th><th>Deger</th></tr>
{{if .TLS}}
<tr><td>Baglanti</td><td>{{if .TLS.Connected}}<span class="pass">Basarili ({{.TLS.Protocol}})</span>{{else}}<span class="fail">Basarisiz</span>{{end}}</td></tr>
<tr><td>Sertifika</td><td>{{if .TLS.CertValid}}<span class="pass">Gecerli</span>{{else}}<span class="fail">Gecersiz</span>{{end}}</td></tr>
<tr><td>Kalan Gun</td><td>{{.TLS.DaysUntilExpiry}}</td></tr>
<tr><td>Issuer</td><td>{{.TLS.Issuer}}</td></tr>
{{end}}
</table>

<h2>Guvenlik Headerlari</h2>
<table>
<tr><th>Header</th><th>Durum</th></tr>
{{if .Headers}}
<tr><td>HSTS</td><td>{{if .Headers.HSTSPresent}}<span class="pass">Mevcut</span>{{else}}<span class="fail">Eksik</span>{{end}}</td></tr>
<tr><td>CSP</td><td>{{if .Headers.CSPPresent}}<span class="pass">Mevcut</span>{{else}}<span class="warn">Eksik</span>{{end}}</td></tr>
<tr><td>X-Frame-Options</td><td>{{if .Headers.XFramePresent}}<span class="pass">Mevcut</span>{{else}}<span class="warn">Eksik</span>{{end}}</td></tr>
<tr><td>X-Content-Type-Options</td><td>{{if .Headers.XCTOPresent}}<span class="pass">Mevcut</span>{{else}}<span class="warn">Eksik</span>{{end}}</td></tr>
{{end}}
</table>

<h2>Email Guvenligi</h2>
<table>
<tr><th>Kayit</th><th>Durum</th></tr>
{{if .Email}}
<tr><td>SPF</td><td>{{if .Email.SPFFound}}<span class="pass">Mevcut</span>{{else}}<span class="fail">Eksik</span>{{end}}</td></tr>
<tr><td>DMARC</td><td>{{if .Email.DMARCFound}}<span class="pass">Mevcut</span>{{else}}<span class="fail">Eksik</span>{{end}}</td></tr>
<tr><td>DKIM</td><td>{{if .Email.DKIMFound}}<span class="pass">Mevcut</span>{{else}}<span class="warn">Bulunamadi</span>{{end}}</td></tr>
<tr><td>DNSSEC</td><td>{{if .Email.DNSSECEnabled}}<span class="pass">Aktif</span>{{else}}<span class="warn">Pasif</span>{{end}}</td></tr>
{{end}}
</table>

<h2>Acikta Kalan Dosyalar</h2>
{{if .Exposed}}
{{if .Exposed.FoundFiles}}
<table><tr><th>Yol</th><th>HTTP Kodu</th></tr>
{{range .Exposed.FoundFiles}}<tr><td class="mono">{{.Path}}</td><td class="fail">{{.Status}}</td></tr>{{end}}
</table>
{{else}}
<p><span class="pass">Hassas dosya tespit edilmedi</span></p>
{{end}}
{{end}}

<h2>Cookie Guvenligi</h2>
{{if .Cookies}}
{{if .Cookies.Cookies}}
<table><tr><th>Isim</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr>
{{range .Cookies.Cookies}}<tr><td class="mono">{{.Name}}</td><td>{{.Secure}}</td><td>{{.HttpOnly}}</td><td>{{.SameSite}}</td></tr>{{end}}
</table>
{{else}}
<p>Cookie bulunamadi</p>
{{end}}
{{end}}

<h2>CORS</h2>
{{if .CORS}}
<table>
<tr><td>Origin yansitiliyor mu</td><td>{{if .CORS.ReflectsOrigin}}<span class="fail">Evet</span>{{else}}<span class="pass">Hayir</span>{{end}}</td></tr>
<tr><td>Tehlikeli konfigurasyon</td><td>{{if .CORS.DangerousMisconfig}}<span class="fail">Evet</span>{{else}}<span class="pass">Hayir</span>{{end}}</td></tr>
</table>
{{end}}

<h2>Alt Domainler</h2>
{{if .Subdomains}}
<p>{{len .Subdomains.Found}} alt domain bulundu ({{.Subdomains.Checked}} kontrol edildi)</p>
{{if .Subdomains.Found}}
<table><tr><th>Alt Domain</th><th>IP Adresleri</th></tr>
{{range .Subdomains.Found}}<tr><td class="mono">{{.Subdomain}}</td><td class="mono">{{join .Addresses}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

<h2>Acik Portlar</h2>
{{if .Ports}}
{{if .Ports.OpenPorts}}
<table><tr><th>Port</th><th>Servis</th></tr>
{{range .Ports.OpenPorts}}<tr><td>{{.Port}}</td><td>{{.Service}}</td></tr>{{end}}
</table>
{{else}}
<p><span class="pass">Riskli servis portu acik degil</span></p>
{{end}}
{{end}}

<h2>Karisik Icerik</h2>
{{if .MixedContent}}
{{if .MixedContent.InsecureRefs}}
<p><span class="fail">{{len .MixedContent.InsecureRefs}} adet http kaynagi bulundu</span></p>
{{else}}
<p><span class="pass">Karisik icerik bulunamadi</span></p>
{{end}}
{{end}}

<h2>Clickjacking Korumasi</h2>
{{if .Clickjacking}}
<p>{{if .Clickjacking.Protected}}<span class="pass">Korumali</span>{{else}}<span class="fail">Korumasiz</span>{{end}}</p>
{{end}}

<h2>WHOIS</h2>
{{if .Whois}}
<table>
<tr><td>Registrar</td><td>{{.Whois.Registrar}}</td></tr>
<tr><td>Olusturma Tarihi</td><td>{{.Whois.CreationDate}}</td></tr>
<tr><td>Bitis Tarihi</td><td>{{.Whois.ExpiryDate}}</td></tr>
</table>
{{end}}

<h2>Itibar Kontrolu</h2>
{{if .Reputation}}
<table>
<tr><td>Kara Liste Kaydi</td><td>{{if .Reputation.DNSBLHits}}<span class="fail">{{len .Reputation.DNSBLHits}} eslesme</span>{{else}}<span class="pass">Temiz</span>{{end}}</td></tr>
<tr><td>Safe Browsing</td><td>{{.Reputation.SafeBrowsing}}</td></tr>
</table>
{{end}}

<h2>Oneriler</h2>
<ul class="rec">
{{range .Recommendations}}<li>{{.}}</li>{{end}}
</ul>

{{end}}
</body>
</html>`

type htmlReportData struct {
	*scanner.FullReport
	GeneratedAt     string
	GradeLetter     string
	TotalScore      int
	Grade           string
	Recommendations []string
}

func joinStrings(items []string) string {
	return strings.Join(items, ", ")
}

func HTMLReportHandler(store *Store) http.HandlerFunc {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"join": joinStrings,
	}).Parse(htmlReportTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/report-html/")
		job := store.GetJob(id)
		if job == nil {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}
		if job.Status != "done" {
			http.Error(w, "scan not completed yet", http.StatusConflict)
			return
		}
		report, ok := job.Result.(*scanner.FullReport)
		if !ok {
			http.Error(w, "report data unavailable", http.StatusInternalServerError)
			return
		}

		data := htmlReportData{
			FullReport:  report,
			GeneratedAt: job.DoneAt.Format("2006-01-02 15:04:05"),
		}
		if report.Score != nil {
			data.TotalScore = report.Score.TotalScore
			data.Grade = report.Score.Grade
			data.Recommendations = report.Score.Recommendations
			if len(report.Score.Grade) > 0 {
				data.GradeLetter = string(report.Score.Grade[0])
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, data)
	}
}
