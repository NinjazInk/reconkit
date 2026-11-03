# reconkit

Small, readable reconnaissance tools for learning web security and for
**authorized** testing. The code is commented to explain *why* each technique
works, not just what it does.

> Only run these against domains and sites you own or have written permission
> to test. Brute-forcing DNS and probing CORS send traffic to the target.

## Install

```bash
pip install -e .            # or: pip install -e '.[test]' to get pytest
```

Requires Python 3.9+, `requests` and `dnspython`.

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
return only those wildcard IPs are discarded.

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
- **CORS**: sends a request with a foreign `Origin` and flags reflection (high if combined with `Allow-Credentials: true`), `null` origin, or `*` (skip with `--no-cors`)

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
  subdomains.py   passive sources, DNS resolver, wildcard detection, brute force
  headers.py      one check_* function per header, scoring
  http.py         shared session, URL normalisation, raw Set-Cookie access
  data/subdomains.txt
tests/
```

Ideas for extending: more passive sources (e.g. SecurityTrails, VirusTotal with
API keys), recursive brute-forcing of discovered subdomains, permutation
generation (`dev-api`, `api2`), and checking CNAMEs against known
takeover-prone services.
