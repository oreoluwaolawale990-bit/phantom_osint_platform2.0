# Phantom OSINT & Cybersecurity Intelligence Platform

**Made by Phantom**

A lightweight FastAPI-based defensive OSINT dashboard designed for Render's Free Web Service. It uses public/keyless sources where possible, bounded concurrency, explicit timeouts, structured error responses, and an SSRF-safe URL auditor.

## Features

- Network/IP intelligence: geolocation, ISP/ASN, hosting/proxy hints, and Tor exit-list correlation.
- Domain intelligence: A, AAAA, MX, TXT, NS, CNAME and SOA records; TLS certificate parsing; Certificate Transparency subdomains; WHOIS.
- Username footprint checks across 30+ public profile URL patterns.
- Email checks: syntax, MX sanity, conservative disposable-domain detection, Gravatar lookup, and XposedOrNot breach lookup.
- URL auditing: security headers, technology hints, robots.txt, sitemap.xml, metadata and safe public-IP resolution.
- Local cyber utilities: hash identification/generation, safe Google dork generation, CIDR math, benign webhook payload generation, and password entropy estimation.

## Important operational notes

Render Free Web Services spin down after 15 minutes without inbound traffic, restart from a clean ephemeral filesystem, and are intended for hobby/testing rather than production workloads. No local database is required by this project. citeturn615853search1

The app pins a released Python version in `render.yaml` through `PYTHON_VERSION`, avoiding dependence on a moving platform default.

XposedOrNot documents the public email endpoint at `/v1/check-email/{email}` and publishes free-tier limits for that endpoint. The application uses a single low-volume request per email lookup.

The URL auditor blocks localhost, private, loopback, link-local, multicast, reserved and unspecified destinations before each request/redirect to reduce SSRF risk.

## Project tree

```text
phantom_osint_platform/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── modules/
│   │   ├── cyber_utils.py
│   │   ├── domain_lookup.py
│   │   ├── email_lookup.py
│   │   ├── ip_lookup.py
│   │   ├── url_auditor.py
│   │   └── username_lookup.py
│   └── static/
│       ├── app.js
│       ├── index.html
│       └── style.css
├── requirements.txt
├── Procfile
├── render.yaml
└── README.md
```

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

## Render deployment

1. Push the project to a Git repository.
2. In Render, create a new **Web Service** from that repository.
3. `render.yaml` can be used with Render Blueprint deployment, or you can copy its build/start commands into the service settings.
4. Keep the plan on **Free** for the intended hobby/test deployment.
5. The health check is `/health`.

The configured Python build command is `pip install -r requirements.txt`, and Uvicorn binds to Render's `$PORT` environment variable.

## Responsible use

Only query systems, accounts and data you are authorized to investigate. The application intentionally avoids authentication bypassing, CAPTCHA solving, rate-limit evasion, password cracking, exploit delivery and arbitrary server-side webhook execution.
