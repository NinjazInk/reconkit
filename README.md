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
- **CORS**: sends a request with a foreign `Origin` and flags reflection (high if combined with `Allow-Credentials: true`), `null` origin, or `*` (skip with `--no-cors`)
- **HTTP to HTTPS redirect**: requests `http://host/` and follows redirects by hand. It flags no redirect, a chain that never reaches HTTPS, extra plain-HTTP hops, and a first hop to a *different* host (the browser then never learns this host's HSTS policy). Skip with `--no-redirect`

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

Ideas for extending: more passive sources (e.g. SecurityTrails, VirusTotal with
API keys), recursive brute-forcing of discovered subdomains, permutation
generation (`dev-api`, `api2`), TLS certificate checks, and a scope file that
refuses out-of-scope targets.
