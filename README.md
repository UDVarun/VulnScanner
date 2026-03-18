# VulnScanner — Web Application Vulnerability Scanner

> A production-grade, full-stack security tool that crawls targets, injects real attack payloads, detects vulnerabilities via HTTP response analysis, maps findings to NVD CVE data, and generates professional PDF reports.

---

## ⚡ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/UDVarun/VulnScanner.git
cd VulnScanner

# 2. Copy environment file
cp .env.example .env
# (Optionally add your NVD API key to .env)

# 3. Run everything with one command
docker compose up --build

# 4. Open in browser
# → Frontend: http://localhost:3000
# → Backend API: http://localhost:5000/api/health
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Frontend (React + Vite)  :3000                         │
│  Dark cyberpunk UI · Real-time dashboard · PDF export   │
└──────────────────────────┬──────────────────────────────┘
                           │ REST + Socket.IO
┌──────────────────────────▼──────────────────────────────┐
│  Backend API (Express)  :5000                            │
│  ├── routes/         — REST endpoints                    │
│  ├── services/       — Scan orchestrator                 │
│  └── engines/                                            │
│       ├── crawlerEngine.js   — BFS endpoint discovery    │
│       ├── payloadEngine.js   — Attack payload catalog    │
│       ├── scannerEngine.js   — HTTP injection testing    │
│       ├── analyzerEngine.js  — Response comparison       │
│       ├── nvdApi.js          — NVD CVE integration       │
│       └── reportEngine.js    — PDF generation            │
└──────────────────────────┬──────────────────────────────┘
                           │ Mongoose
┌──────────────────────────▼──────────────────────────────┐
│  MongoDB  :27017                                         │
│  Collections: scans · vulnerabilities                    │
└─────────────────────────────────────────────────────────┘
```

---

## 🛡 Vulnerability Detection

| Type | Detection Method |
|------|-----------------|
| **SQL Injection** | SQL error pattern matching, response time, length diff |
| **XSS (Reflected)** | Payload reflection in response body |
| **Missing Security Headers** | X-Frame-Options, CSP, HSTS, X-XSS-Protection, X-Content-Type-Options |
| **Authentication Bypass** | Unauthenticated access to admin-like paths |
| **Path Traversal** | System file content detection in response |
| **Header Injection** | CRLF injection in HTTP headers |

All findings are enriched with real CVE IDs and CVSS scores from the [NVD API](https://nvd.nist.gov/).

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/results/:id` | Get scan + vulnerabilities |
| `GET` | `/api/report/:id` | Download PDF report |
| `GET` | `/api/health` | Health check |

---

## 🧪 Test Targets

Safe, intentionally vulnerable targets for testing:

- `http://testphp.vulnweb.com` — SQLi, XSS, headers
- `http://www.dvwa.co.uk` — DVWA (run locally via Docker)
- `http://juice-shop.herokuapp.com` — OWASP Juice Shop

> ⚠️ **Legal Notice**: Only scan systems you own or have explicit permission to test.

---

## 📦 Services

| Service | Port | Tech |
|---------|------|------|
| Frontend | 3000 | React + Vite + Nginx |
| Backend | 5000 | Node.js + Express + Socket.IO |
| Database | 27017 | MongoDB 7 |

---

## 🔧 Kali Linux Setup

```bash
# Automated setup (installs Node.js, Docker, Git)
chmod +x setup.sh
sudo ./setup.sh
```

---

## 📄 Environment Variables

See [`.env.example`](.env.example) for all available configuration options.

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://mongodb:27017/vulnscanner` | MongoDB connection |
| `PORT` | `5000` | Backend port |
| `NVD_API_KEY` | *(empty)* | Optional NVD API key for higher rate limits |

---

## 📊 Database Schema

**Scans**
```js
{ targetUrl, status, progress, totalEndpoints, summary, createdAt, completedAt }
```

**Vulnerabilities**
```js
{ scanId, type, severity, cveId, cvssScore, endpoint, parameter, payload, evidence, confidence, recommendation }
```

---

## 🏆 Built For

- Academic evaluation & project submissions
- Technical interview demonstrations
- SOP/resume portfolio
- Real-world security auditing (use responsibly)
