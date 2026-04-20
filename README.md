# 🔍 Security Scanner

A minimal viable web application for basic security scanning, built with **FastAPI** + **SQLite**.

![Landing Page](https://github.com/user-attachments/assets/903c2d07-ae00-4343-9dd0-175590356e77)

## Features

- **Authentication** — Register, login, logout with bcrypt password hashing and JWT tokens; brute-force protection (account locked after 5 failed attempts in 5 minutes)
- **Web Crawler** — BFS crawler that discovers internal pages, query parameters, HTML forms, and common API endpoints up to a configurable depth (max 5), with robots.txt support (enabled by default, configurable per scan)
- **Vulnerability Scanner** — Non-intrusive checks for reflected XSS, SQLi signatures/time heuristics, open redirects, directory listing exposure, missing security headers, insecure cookies, and technology/version disclosure
- **Rate-Limited Scanning** — Request pacing and retry/backoff controls to reduce load on target systems
- **Reporting Dashboard** — HTML/JS dashboard with scan history, vulnerability details modal, plus JSON and HTML export

### Modular CLI Security Scanner (secscan)

This repository now also includes a standalone modular scanner package for authorized web application testing:

- `secscan/crawler` — BFS crawler with link/form/query/JS endpoint extraction, depth, duplicate filtering, domain scope, robots.txt support, and rate limiting
- `secscan/fingerprint` — server/framework/library detection with version extraction and mock vulnerable-version matching
- `secscan/scanner` — async queue-based scanner core with plugin execution
- `secscan/checks` — plugin checks for OWASP-style findings (passive + light active)
- `secscan/reporter` — JSON/HTML/CSV reporting with summary stats and severity filtering
- `secscan/utils` — shared config, models, logging, HTTP, and session persistence for resume support

Security checks implemented as plugins:

- Headers check
- SSL/TLS certificate check
- Cookie security check
- Input reflection check (XSS indicator)
- SQL error exposure check
- Open redirect check
- Directory and file exposure check
- Sensitive data exposure scan
- JavaScript analysis
- CORS misconfiguration check

---

## Project Structure

```
app/
├── main.py               # FastAPI entry point, mounts routes & templates
├── core/
│   ├── config.py         # Settings (env vars with .env support)
│   └── security.py       # JWT creation/verification, bcrypt, brute-force counter
├── db/
│   └── database.py       # SQLAlchemy async engine, session factory, init_db()
├── models/
│   ├── user.py           # User ORM model
│   └── scan.py           # Scan & Vulnerability ORM models
├── routes/
│   ├── auth.py           # POST /auth/register  POST /auth/login  GET /auth/me
│   ├── scan.py           # POST /scan           GET /scan/{id}
│   ├── report.py         # GET /reports         GET /reports/{id}  DELETE /reports/{id}
│   └── dependencies.py   # Shared FastAPI deps (get_current_user)
├── services/
│   ├── crawler.py        # Async BFS crawler + form/API target discovery
│   └── scanner.py        # XSS/SQLi checks across query/form/json surfaces
├── templates/            # Jinja2 HTML templates
│   ├── index.html        # Landing page
│   ├── login.html        # Login form
│   ├── register.html     # Registration form
│   └── dashboard.html    # Main scan dashboard
└── static/
    ├── style.css         # Application styles
    ├── auth.js           # Login/register form logic
    └── dashboard.js      # Dashboard: scan list, new scan, vuln modal
```

---

## Quick Start

### 1. Clone & install dependencies

```bash
git clone https://github.com/noxx-code/scanner.git
cd scanner
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. (Optional) Configure via environment variables

Copy the example and edit as needed:

```bash
cp .env.example .env
```

Key settings (all have sensible defaults):

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `change-me-…` | JWT signing key — **change in production** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT TTL |
| `DATABASE_URL` | `sqlite+aiosqlite:///./scanner.db` | Database location |
| `DEFAULT_CRAWL_DEPTH` | `2` | Default crawler depth |
| `MAX_LOGIN_ATTEMPTS` | `5` | Brute-force threshold |
| `API_COMMON_ENDPOINTS` | `/api,/rest,...` | Seed list for API endpoint probing |
| `API_BRUTEFORCE_ENABLED` | `true` | Enables basic API endpoint brute-force checks |
| `SCAN_JSON_ENDPOINTS` | `true` | Enables JSON-body scanning for API targets |
| `SQLI_TIME_THRESHOLD_SECONDS` | `2.5` | Threshold for time-based SQLi heuristics |
| `CRAWL_RESPECT_ROBOTS_TXT` | `true` | Respect target robots.txt by default |
| `CRAWL_REQUESTS_PER_SECOND` | `5.0` | Crawl request pacing |
| `SCANNER_REQUESTS_PER_SECOND` | `8.0` | Scanner request pacing |

### 3. Run the application

```bash
uvicorn app.main:app --reload
```

If you prefer to execute Python directly, use:

```bash
python -m app.main
```

Avoid running `python app/main.py`; that treats the file as a script and breaks package imports because the project root is not added to `sys.path`.

Open your browser at **http://localhost:8000**

### 4. Run the modular scanner CLI

```bash
python -m secscan https://example.com --depth 2 --threads 20 --rate-limit 5 --output all
```

CLI options:

- `--depth`
- `--threads`
- `--output` (`json`, `html`, `csv`, `all`)
- `--rate-limit`
- `--allow-external`
- `--ignore-robots`
- `--save-session <name>`
- `--resume <name>`

Generated reports are written to `reports/` by default.

Example run and sample outputs are included in:

- `examples/sample_run.txt`
- `examples/sample_report.json`
- `examples/sample_report.html`

---

## API Reference

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | — | Create a new account |
| `POST` | `/auth/login` | — | Get a JWT access token |
| `POST` | `/auth/logout` | Bearer | Invalidate session (client-side) |
| `GET` | `/auth/me` | Bearer | Current user profile |

### Scans

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/scan` | Bearer | Start a new scan (runs in background) |
| `GET` | `/scan/{id}` | Bearer | Get scan + vulnerabilities |

### Reports

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/reports` | Bearer | List all scans for the current user |
| `GET` | `/reports/{id}` | Bearer | Full report for one scan |
| `GET` | `/reports/{id}/json` | Bearer | Structured JSON report with summary, severity counts, and remediation |
| `GET` | `/reports/{id}/html` | Bearer | Printable HTML report export |
| `DELETE` | `/reports/{id}` | Bearer | Delete one scan report and related vulnerabilities |

Interactive docs: **http://localhost:8000/docs**

---

## Screenshots

| Register | Dashboard |
|---|---|
| ![Register](https://github.com/user-attachments/assets/8c5fb872-078c-4543-8a09-97f2e7120f0b) | ![Dashboard](https://github.com/user-attachments/assets/6cfaff4c-63a0-4d82-bce3-a1fa74c38295) |

---

## Security Notes

- Passwords are stored as **bcrypt** hashes — plain-text passwords are never persisted.
- JWTs are signed with HS256; the `SECRET_KEY` **must** be changed before deploying.
- Scanner payloads are *diagnostic only* — they do not write, delete, or modify data on the target.
- Always obtain explicit permission before scanning any target.