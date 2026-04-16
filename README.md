# 🔍 Security Scanner

A minimal viable web application for basic security scanning, built with **FastAPI** + **SQLite**.

![Landing Page](https://github.com/user-attachments/assets/903c2d07-ae00-4343-9dd0-175590356e77)

## Features

- **Authentication** — Register, login, logout with bcrypt password hashing and JWT tokens; brute-force protection (account locked after 5 failed attempts in 5 minutes)
- **Web Crawler** — BFS crawler that discovers internal pages and query parameters up to a configurable depth (max 5)
- **Vulnerability Scanner** — Checks discovered parameters for reflected XSS and error-based SQL injection
- **Reporting Dashboard** — Clean HTML/JS frontend showing scan history, status badges, vulnerability counts, and a detail modal

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
│   ├── report.py         # GET /reports         GET /reports/{id}
│   └── dependencies.py   # Shared FastAPI deps (get_current_user)
├── services/
│   ├── crawler.py        # Async BFS web crawler
│   └── scanner.py        # XSS & SQLi payload testing
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

### 3. Run the application

```bash
uvicorn app.main:app --reload
```

Open your browser at **http://localhost:8000**

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