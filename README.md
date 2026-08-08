# SecAudit

A lightweight website security audit tool built with Go.

SecAudit performs automated security checks for websites and domains, providing a security score and detailed report covering TLS, HTTP headers, DNS configuration, email security, and exposed sensitive files.

## Features

- Pure Go implementation
- Lightweight and fast scanning
- No heavy external dependencies
- REST API support
- Web dashboard
- Async scan jobs
- JSON-based reports
- Security score system

## Security Checks

### TLS / SSL Analysis

Checks:

- HTTPS availability
- TLS protocol versions
- Cipher information
- Certificate validity
- Certificate expiration
- Certificate chain details

### HTTP Security Headers

Analyzes important security headers:

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Server information leakage
- X-Powered-By leakage

### DNS Security

Checks:

- SPF records
- DMARC policy
- DKIM availability
- CAA records
- DNSSEC indicators

### Exposed File Detection

Detects common accidentally exposed files:

- `.git/config`
- `.env`
- Backup files
- Configuration files
- Debug files
- Common sensitive paths

## Security Score

SecAudit calculates a weighted security score based on detected issues.

Example:

```
Security Score: 87/100

Grade: A

Issues:
- Missing CSP header
- DMARC policy not enforced
```

## Project Structure

```text
secaudit/
├── cmd/
│   ├── api/
│   │   └── main.go
│   └── scan/
│       └── main.go
│
├── internal/
│   ├── api/
│   │   ├── store.go
│   │   ├── ratelimit.go
│   │   ├── handlers.go
│   │   └── dashboard.go
│   │
│   ├── rawdns/
│   │   └── rawdns.go
│   │
│   └── scanner/
│       ├── tls.go
│       ├── headers.go
│       ├── emailsec.go
│       ├── exposed.go
│       ├── ownership.go
│       ├── score.go
│       └── orchestrator.go
│
├── go.mod
├── Dockerfile
├── LICENSE
└── README.md
```

## Requirements

- Go 1.22+

## Installation

Clone the repository:

```bash
git clone https://github.com/username/secaudit.git
cd secaudit
```

Build:

```bash
go build ./...
```

## Running

Start API server:

```bash
go run ./cmd/api
```

Default:

```
http://localhost:8080
```

Run CLI scanner:

```bash
go run ./cmd/scan -domain example.com
```

## API Usage

### Start Scan

```
POST /api/scan
```

Request:

```json
{
  "domain": "example.com"
}
```

Response:

```json
{
  "job_id": "abc123",
  "status": "queued"
}
```

### Get Report

```
GET /api/report/{job_id}
```

### Scan History

```
GET /api/history/{domain}
```

## Use Cases

SecAudit can be used for:

- Website security reviews
- Developer security checks
- Agency client reports
- Hosting audits
- SSL verification
- Email security validation
- Basic attack surface discovery

## Roadmap

- Persistent database storage
- Scheduled scans
- PDF report export
- Notifications
- Multi-user dashboard
- Team management
- White-label reports

## Security Notice

SecAudit is designed for defensive security auditing.

Only scan domains and systems you own or have explicit permission to test.

## License

MIT License
