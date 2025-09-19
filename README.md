# Flask Vulnerabilities Lab — README

**Purpose**  
This small lab app demonstrates _vulnerable vs safe_ patterns for **SQL Injection**, **RCE (insecure subprocess use)**, **SSRF** and **XSS (Cross-Site Scripting)** inside a single Flask app. It is for **educational** use only so you can learn how vulnerabilities look and how to fix them.

> **Important — read before running**
>
> - Run **only** in an isolated lab (local VM / Kali / snapshot). Do **NOT** expose this app to the Internet.
> - Do **not** use these examples against third-party systems — doing so is illegal and unethical.
> - The app contains intentionally insecure endpoints.
> - Create a VM snapshot before testing so you can revert.

---

## Files included

- `app_vulns.py` — Flask app with vulnerable and safe endpoints.
- `requirements.txt` — packages required.
- (optional) `lab_test.db` — will be created automatically on first run.

---

## Requirements

- Python 3.8+
- Recommended: run inside a virtual environment

`requirements.txt`

```text
flask==3.1.2
requests==2.31.0
```

---

## Setup & run (Linux / macOS)

```bash
# 1. create and activate virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 2. install dependencies
pip install -r requirements.txt

# 3. start the app
python app_vulns.py

# App will listen on 127.0.0.1:5000 by default
# Visit http://127.0.0.1:5000/
```

### Alternative: using the flask CLI

```bash
# from same folder, with venv active
flask --app app_vulns run --host=127.0.0.1 --port=5000
```

---

## Setup & run (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app_vulns.py
```

---

## Endpoints (summary)

Open `http://127.0.0.1:5000/` for a short note.

### SQL Injection

- `GET /sql_vuln?username=<value>`
  - Vulnerable: builds SQL by string concatenation. Use to see how query changes.
  - Example payload: `' UNION SELECT 1,sqlite_version()--`
- `GET /sql_safe?username=<value>`
  - Safe: uses parameterized query.

### RCE (Remote Code Execution demonstration)

- `POST /rce_vuln` (JSON) — body `{"cmd":"<command>"}`
  - Vulnerable: runs `subprocess.run(..., shell=True)` with user input (unsafe).
  - Example benign command: `{"cmd":"echo hello"}`
- `POST /rce_safe` (JSON) — body `{"filename":"<name>"}`
  - Safe: validates filename and calls subprocess with argument list (no `shell=True`).

### SSRF (Server-Side Request Forgery)

- `GET /fetch_vuln?url=<url>`
  - Vulnerable: performs `requests.get` on any supplied URL (dangerous).
- `GET /fetch_safe?url=<url>`
  - Safer: whitelist of allowed hosts + DNS resolution checks (demo only).

### XSS (Cross-Site Scripting)

- `GET /xss_vuln?name=<value>`
  - Vulnerable: reflected XSS - user input directly embedded in HTML without escaping.
  - Example payload: `?name=<script>alert('XSS')</script>`
- `GET /xss_safe?name=<value>`
  - Safe: properly escapes HTML entities to prevent XSS.
- `GET/POST /comments_vuln`
  - Vulnerable: stored XSS - user comments stored and displayed without escaping.
  - Form fields: `author` and `content`
- `GET/POST /comments_safe`
  - Safe: validates input and escapes HTML entities when displaying comments.

---

## Quick test examples (curl)

### SQL

```bash
# vulnerable
curl "http://127.0.0.1:5000/sql_vuln?username=alice"

# safe
curl "http://127.0.0.1:5000/sql_safe?username=alice"
```

### RCE

```bash
# vulnerable - benign command
curl -X POST -H "Content-Type: application/json" -d '{"cmd":"echo hello"}' http://127.0.0.1:5000/rce_vuln

# safe - list current directory (filename param)
curl -X POST -H "Content-Type: application/json" -d '{"filename":"."}' http://127.0.0.1:5000/rce_safe
```

### SSRF

```bash
# vulnerable - fetch a public URL (benign)
curl "http://127.0.0.1:5000/fetch_vuln?url=https://example.com"

# safe - only allowed hosts (default example.com and httpbin.org)
curl "http://127.0.0.1:5000/fetch_safe?url=https://example.com"
```

### XSS

```bash
# vulnerable - reflected XSS
curl "http://127.0.0.1:5000/xss_vuln?name=John"

# safe - escaped input
curl "http://127.0.0.1:5000/xss_safe?name=John"

# vulnerable - stored XSS (view comments)
curl "http://127.0.0.1:5000/comments_vuln"

# vulnerable - stored XSS (post comment)
curl -X POST -d "author=Alice&content=Hello world" "http://127.0.0.1:5000/comments_vuln"

# safe - stored XSS (view comments safely)
curl "http://127.0.0.1:5000/comments_safe"

# safe - stored XSS (post comment safely)
curl -X POST -d "author=Alice&content=Hello world" "http://127.0.0.1:5000/comments_safe"
```

---

## How to test safely

- Use only **public, benign URLs** for SSRF testing (e.g. `https://example.com`).
- For RCE demonstration use **non-destructive** commands like `echo` or `ls` on a controlled directory.
- For SQL testing use the provided `users` table only (no external DB). The app uses a local SQLite file created in the working directory.
- For XSS testing use **benign payloads** like `<script>alert('XSS')</script>` or `<img src=x onerror=alert('XSS')>` - avoid malicious payloads that could harm your system.

---

## What each vulnerable pattern teaches

- **SQL Injection**: never build SQL by concatenating raw user input — use parameterized queries / ORM.
- **RCE**: avoid `shell=True` with untrusted input; prefer argument lists and strict validation/whitelists.
- **SSRF**: never allow arbitrary URL fetches from user input; implement whitelists and IP/DNS checks, restrict outbound network via firewall/proxy.
- **XSS**: always escape user input when displaying in HTML; use Content Security Policy (CSP); validate and sanitize input on both client and server side.

---

## Mitigations / best practices (short)

- Parameterize database queries (prepared statements).
- Use frameworks/ORMs and least-privilege DB users (no root/db owner creds).
- Avoid `shell=True`. Validate, sanitize or whitelist inputs.
- Use whitelists and resolve hostnames to check for private IP ranges for outgoing requests.
- Log and alert suspicious requests. Use egress controls at network level.
- Always run web apps under HTTPS and secure cookies (for session attacks).
- Escape all user input when displaying in HTML (`html.escape()` in Python).
- Implement Content Security Policy (CSP) headers to prevent XSS.
- Validate and sanitize input on both client and server side.
- Use templating engines that auto-escape by default (Jinja2, etc.).

---

## Troubleshooting

- `flask: Could not locate a Flask application` — make sure you run `python app_vulns.py` or `flask --app app_vulns run`. Also ensure you are in the same directory as `app_vulns.py`.
- If port 5000 is busy, stop the process using it or change `app.run(host=..., port=...)` in the file.
