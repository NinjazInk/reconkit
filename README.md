# reconkit

Small, readable reconnaissance tools for web security and for
authorized testing. The code is commented to explain *why* each technique
works, not just what it does.

> Only run these against domains and sites you own or have written permission
> to test. Brute-forcing DNS and probing CORS send traffic to the target.

## Installation (step by step)

### Step 1: Install Python

reconkit requires **Python 3.10 or newer**.

**Check if you already have it** — open a terminal (Command Prompt on Windows,
Terminal on Mac/Linux) and run:

```
python --version
```

If that says "not recognized" or shows a version below 3.10, install Python:

- **Windows**: Download from https://www.python.org/downloads/
  - **IMPORTANT**: On the first installer screen, check the box that says
    **"Add python.exe to PATH"** before clicking Install. If you miss this,
    nothing else will work from the command prompt.
  - After installing, **close and reopen** your Command Prompt so the PATH
    change takes effect.
- **Mac**: `brew install python` (if you have Homebrew), or download from
  https://www.python.org/downloads/
- **Linux**: `sudo apt install python3 python3-pip` (Debian/Ubuntu) or
  `sudo dnf install python3 python3-pip` (Fedora)

**Verify Python is working:**

```
python --version
```

You should see something like `Python 3.12.4`. If Windows still doesn't
recognise `python`, try `py --version` instead — and use `py` wherever this
guide says `python`.

### Step 2: Install Git (if you don't have it)

```
git --version
```

If that says "not recognized":

- **Windows**: Download from https://git-scm.com/download/win — use the
  default options. Close and reopen Command Prompt after installing.
- **Mac**: Run `xcode-select --install` or `brew install git`
- **Linux**: `sudo apt install git` or `sudo dnf install git`

### Step 3: Download reconkit

Pick a folder where you want the tool to live. For example, to put it in a
folder called `cytools` on your desktop:

**Windows:**
```
mkdir %USERPROFILE%\Desktop\cytools
```
```
cd %USERPROFILE%\Desktop\cytools
```
```
git clone https://github.com/NinjazInk/reconkit.git
```
```
cd reconkit
```

**Mac / Linux:**
```
mkdir -p ~/Desktop/cytools
```
```
cd ~/Desktop/cytools
```
```
git clone https://github.com/NinjazInk/reconkit.git
```
```
cd reconkit
```

You should now be inside the `reconkit` folder. Verify with:

```
dir
```

(or `ls` on Mac/Linux). You should see files like `pyproject.toml`,
`README.md`, and a `reconkit/` folder.

### Step 4: Install dependencies

reconkit needs two Python libraries:

| Library | What it does |
|---|---|
| **requests** | Makes HTTP requests to web servers |
| **dnspython** | DNS lookups with CNAME and retry support |

Install them:

```
python -m pip install requests dnspython
```

If you see a "pip not found" error, try:
```
py -m pip install requests dnspython
```

### Step 5: Install reconkit

Still inside the `reconkit` folder, run:

```
python -m pip install -e .
```

The `-e` means "editable" — Python links to the files in this folder rather
than copying them, so any updates you pull with `git pull` take effect
immediately.

### Step 6: Verify it works

**Option A** — if `pip install -e .` succeeded without errors:

```
reconkit --version
```

Should print `reconkit 0.1.0`.

**Option B** — if `reconkit` is "not recognized" (Windows PATH issue), run it
through Python instead. This always works:

```
python -m reconkit.cli --version
```

If Option A doesn't work but Option B does, use `python -m reconkit.cli`
everywhere this guide says `reconkit`. This is a Windows PATH issue — the
`reconkit.exe` command was installed to a Scripts folder that isn't in your
PATH. It doesn't affect functionality.

### Quick test

Run a header check against a public site you own or have permission to test:

```
reconkit headers https://example.com
```

Or via Python:

```
python -m reconkit.cli headers https://example.com
```

You should see a grade (A-F), a score, and a list of findings.

### Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized | Close and reopen Command Prompt. If still broken, reinstall Python with "Add to PATH" checked. |
| `pip` not found | Use `python -m pip` instead of `pip`. |
| `reconkit` not recognized | Use `python -m reconkit.cli` instead. |
| `git` not recognized | Install Git (Step 2) and reopen Command Prompt. |
| `ModuleNotFoundError: requests` | Run Step 4 again — dependencies didn't install. |
| Permission denied (Mac/Linux) | Add `--user` to pip commands: `python -m pip install --user -e .` |

## Full scan (start here)

```bash
reconkit scan example.com                         # passive enumeration + audit every live host
reconkit scan example.com --brute -o report.json  # add wordlist guessing, save full JSON
reconkit scan example.com --limit 20 --http-threads 20 --no-cors
```

`scan` chains everything: it enumerates subdomains, keeps the ones that
resolve, then for each host checks for a **dangling CNAME** (possible subdomain
takeover) and grades its **security headers**, including the HTTP-to-HTTPS
redirect. Output is one table sorted worst-first, with takeover leads listed
separately:

```
HOST               HTTP  GRADE  HIGH MED LOW  TOP ISSUE
old.example.com    -     -                    no address (CNAME target does not resolve)
www.example.com    200   C         1   0   3  script-src allows 'unsafe-inline'
api.example.com    200   B         0   1   2  HSTS missing

Possible subdomain takeovers (1) - verify manually:
  LIKELY old.example.com -> old-site.herokuapp.com  [Heroku]
         CNAME target old-site.herokuapp.com does not resolve (NXDOMAIN)
```

It accepts all of the enumeration options below (`--brute`, `-w`, `--sources`,
`--no-passive`, `-n`, `-t`).

### Subdomain takeover detection

A takeover is possible when `shop.example.com` is a CNAME to a hosted service
(`old.myshopify.com`, `acme.github.io`, an S3 bucket ...) but the resource on
that service was deleted: whoever claims the same name on the service then
controls content on `shop.example.com`. reconkit flags a host when:

- the CNAME chain ends in **NXDOMAIN** (the alias points at nothing). The
  resolver asks for the CNAME record directly in this case, because a normal
  lookup just reports "does not exist" and hides the alias; or
- the service answers with its **"nothing configured here" page**, matched
  against fingerprints for about 15 common providers (GitHub Pages, Heroku, S3,
  Azure, Shopify, Fastly, Netlify, ...) in `reconkit/takeover.py`.

`LIKELY` means a known provider matched; `POSSIBLE` means the target is gone but
the provider isn't recognised. Both are leads only: reconkit never tries to claim
anything. Confirm manually, and check
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) for
which providers are currently exploitable, since error pages change.

## Subdomain enumeration

```bash
reconkit subdomains example.com                    # passive sources + DNS resolution
reconkit subdomains example.com --brute            # also guess names from a wordlist
reconkit subdomains example.com --brute -w big.txt --no-passive -t 100
reconkit subdomains example.com --alive-only --json
```

How it works:

| Technique | Source | Touches target? |
|---|---|---|
| Certificate Transparency | crt.sh, CertSpotter: every public TLS cert is logged with the hostnames it covers | No |
| Passive DNS | HackerTarget: historical DNS observations | No |
| Brute force | Resolve `word.example.com` for each wordlist entry | Yes (DNS queries) |

**Wildcard DNS:** if `*.example.com` resolves, every guess "succeeds". Before
brute-forcing, reconkit resolves a few random labels; brute-force hits that
return only those wildcard IPs are discarded. For CDN-hosted domains where
many real subdomains share the same IP pool, reconkit also compares HTTP
response fingerprints (status code + content length) to tell real sites apart
from the wildcard default page.

Passive results are then resolved, so you can see which names are still live
(names in CT logs are often long dead). A CNAME pointing at an unclaimed cloud
resource is worth a look as a possible subdomain-takeover candidate.

Options: `--sources crtsh,certspotter,hackertarget`, `-n 1.1.1.1` (custom
resolver, repeatable), `--no-resolve`, `-q`.

The built-in wordlist (`reconkit/data/subdomains.txt`) has 163 entries. Use
something like SecLists' `Discovery/DNS` lists for real work.

## Security header analysis

```bash
reconkit headers https://example.com
reconkit headers example.com -v        # include info-level notes and raw values
reconkit headers example.com --json
```

Every command also takes `-o FILE` to save the full results as JSON.

Each finding has a severity, a **why**, and a **fix**. The checks:

- **Strict-Transport-Security**: missing, `max-age` too short/zero, no `includeSubDomains`/`preload`; site not on HTTPS at all
- **Content-Security-Policy**: missing, report-only, no `script-src`/`default-src`, `'unsafe-inline'` (unless nonces/hashes/`'strict-dynamic'`), `'unsafe-eval'`, wildcard / `https:` / `data:` script sources, missing `object-src`, `base-uri`, `frame-ancestors`
- **Clickjacking**: no `X-Frame-Options` and no `frame-ancestors`; deprecated `ALLOW-FROM`; invalid values
- **X-Content-Type-Options**: not `nosniff`
- **Referrer-Policy**: missing or leaky (`unsafe-url`, `no-referrer-when-downgrade`)
- **Permissions-Policy**: missing
- **X-XSS-Protection**: legacy auditor enabled
- **Information disclosure**: versioned `Server`, `X-Powered-By`, `X-AspNet-Version`, …
- **Cookies**: missing `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` without `Secure`
- **COOP / COEP / CORP**: missing Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy (info-level)
- **`__Host-` cookie prefix**: validates that `__Host-` cookies have `Secure`, `Path=/`, and no `Domain` attribute
- **CORS**: sends a request with a foreign `Origin` and flags reflection (high if combined with `Allow-Credentials: true`), `null` origin, or `*` (skip with `--no-cors`)
- **HTTP to HTTPS redirect**: requests `http://host/` and follows redirects by hand. It flags no redirect, a chain that never reaches HTTPS, extra plain-HTTP hops, and a first hop to a *different* host (the browser then never learns this host's HSTS policy). Skip with `--no-redirect`
- **TLS certificate errors**: expired, self-signed, or misconfigured certificates are surfaced as high-severity findings
- **Meta CSP**: parses `<meta http-equiv="Content-Security-Policy">` from the page body when the header is absent (handles both single- and double-quoted attributes)
- **Dual CSP headers**: detects when the server sends multiple CSP headers (which `requests` comma-joins) and warns about it
- **Bot/WAF detection**: recognises Cloudflare, Akamai, DDoS-Guard, Sucuri challenge pages and marks them as "BLOCKED" instead of grading meaningless headers
- **Per-path analysis**: `--paths /,/api,/admin` audits multiple paths, since different endpoints can have different headers

The score starts at 100 and subtracts 25 / 12 / 5 for high / medium / low
findings, giving a grade from A to F. If the response is HTTP 4xx/5xx the output
warns you: error pages from a WAF or proxy often carry different headers than
the real application.

## Development

```bash
python -m pytest -q
```

Tests are offline: HTTP sessions and DNS resolvers are faked.

```
reconkit/
  cli.py          argparse front end, text + JSON output
  scan.py         enumerate -> audit every live host, worst-first
  subdomains.py   passive sources, DNS resolver, wildcard + dangling-CNAME detection, brute force
  headers.py      one check_* function per header, redirect check, scoring
  takeover.py     provider fingerprints for dangling-CNAME detection
  http.py         shared session, URL normalisation, raw Set-Cookie access
  data/subdomains.txt
tests/
```

## Global options

| Flag | Description |
|---|---|
| `--user-agent "Mozilla/5.0 ..."` | Custom User-Agent header (default: `reconkit/0.1`) |
| `--version` | Print version and exit |

The default UA is fingerprintable by WAFs. Use `--user-agent` with a common
browser string if you're getting blocked.

## Ideas for extending

- More passive sources (SecurityTrails, VirusTotal with API keys)
- Recursive brute-forcing of discovered subdomains
- Permutation generation (`dev-api`, `api2`)
- A scope file that refuses out-of-scope targets
