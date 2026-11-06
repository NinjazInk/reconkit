# reconkit

Subdomain enumeration and security header analysis for authorized testing.

> Only run these against domains you own or have written permission to test.

## Install

**Prerequisites:** Python 3.10+ and Git.
- Python: https://www.python.org/downloads/ — on Windows, check **"Add python.exe to PATH"** during install
- Git: https://git-scm.com/downloads

```
git clone https://github.com/NinjazInk/reconkit.git
cd reconkit
python -m pip install requests dnspython
python -m pip install -e .
```

**Verify:** `reconkit --version` — if "not recognized" on Windows, use `python -m reconkit.cli` instead.

## Usage

**Full scan** — find subdomains, audit headers, check for takeovers:
```
reconkit scan example.com
reconkit scan example.com --brute -o report.json
```

**Subdomains only:**
```
reconkit subdomains example.com
reconkit subdomains example.com --brute --alive-only
```

**Headers only:**
```
reconkit headers https://example.com -v
reconkit headers example.com --paths /,/api,/admin
```

All commands accept `--json` and `-o FILE` for JSON output.

## What it checks

**Subdomains:** Certificate Transparency logs (crt.sh, CertSpotter), passive DNS (HackerTarget), and optional wordlist brute-force with wildcard filtering (CDN-aware). Detects dangling CNAMEs for subdomain takeover across ~15 providers.

**Security headers:** HSTS, CSP (including meta tags and dual-header detection), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, cookie flags, `__Host-` prefix validation, CORS origin reflection, HTTP-to-HTTPS redirects, TLS certificate errors, and server version disclosure. Detects Cloudflare/Akamai/DDoS-Guard/Sucuri bot protection pages.

Scores 100 minus 25/12/5 per high/medium/low finding. Grades: A (90+), B (75+), C (60+), D (40+), F.

## Options

| Flag | Description |
|---|---|
| `--brute` | Wordlist brute-force (subdomains/scan) |
| `-w FILE` | Custom wordlist |
| `--paths /,/api` | Check multiple paths (headers/scan) |
| `--user-agent "..."` | Custom User-Agent string |
| `-v` | Verbose — show info findings and raw values |
| `-t N` | DNS threads (default 50) |
| `--no-cors` | Skip CORS probe |
| `--no-redirect` | Skip HTTP-to-HTTPS redirect check |
| `-n IP` | Custom DNS server (repeatable) |

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized | Reinstall Python with "Add to PATH" checked, reopen terminal |
| `reconkit` not recognized | Use `python -m reconkit.cli` instead |
| `ModuleNotFoundError` | Re-run `python -m pip install requests dnspython` |
