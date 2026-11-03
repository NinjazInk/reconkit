"""Security header analysis.

Each check produces a Finding with a severity and a *why*: the point is to
learn what each header defends against, not just to tick boxes.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urljoin, urlparse

import requests

from .http import DEFAULT_TIMEOUT, get_set_cookies, make_session, normalize_url

SEVERITY_WEIGHT = {"high": 25, "medium": 12, "low": 5, "info": 0}
SEVERITY_ORDER = ["high", "medium", "low", "info"]


@dataclass
class Finding:
    header: str
    severity: str  # high | medium | low | info
    title: str
    why: str
    fix: str = ""
    value: str | None = None


@dataclass
class HeaderReport:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    findings: list[Finding]
    score: int
    grade: str
    blocked_by: str | None = None
    meta_csp: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:  # per spec, duplicates after the first are ignored
            directives[name] = [t for t in tokens[1:]]
    return directives


def grade_for(score: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


CHALLENGE_SIGNATURES = [
    (r"cf-mitigated.*challenge", "Cloudflare"),
    (r"<title>\s*just a moment", "Cloudflare"),
    (r"cdn-cgi/challenge-platform", "Cloudflare"),
    (r"managed challenge", "Cloudflare"),
    (r"akamai bot manager", "Akamai"),
    (r"access denied.*reference\s*#", "Akamai"),
    (r"<title>\s*ddos-guard", "DDoS-Guard"),
    (r"<title>\s*attention required.*cloudflare", "Cloudflare"),
    (r"<title>\s*access denied", "WAF"),
    (r"sucuri website firewall", "Sucuri"),
    (r"you have been blocked", "WAF"),
    (r"_cf_chl_opt", "Cloudflare"),
]


def detect_challenge_page(resp: requests.Response) -> str | None:
    try:
        body = resp.text[:50_000].lower()
    except Exception:
        body = ""
    for pattern, provider in CHALLENGE_SIGNATURES:
        if re.search(pattern, body, re.I | re.S):
            if resp.status_code in (403, 503):
                return provider
    cf_header = resp.headers.get("cf-mitigated")
    if cf_header and "challenge" in cf_header.lower():
        return "Cloudflare"
    server = resp.headers.get("Server", "").lower()
    if resp.status_code == 503 and "ddos-guard" in server:
        return "DDoS-Guard"
    return None


def extract_meta_csp(body: str) -> str | None:
    for q in ('"', "'"):
        m = re.search(
            rf'<meta\s[^>]*http-equiv\s*=\s*{q}Content-Security-Policy{q}'
            rf'\s[^>]*content\s*=\s*{q}([^{q}]+){q}',
            body, re.I | re.S,
        )
        if m:
            return m.group(1)
        m = re.search(
            rf'<meta\s[^>]*content\s*=\s*{q}([^{q}]+){q}'
            rf'\s[^>]*http-equiv\s*=\s*{q}Content-Security-Policy{q}',
            body, re.I | re.S,
        )
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Individual checks. Each takes a case-insensitive header mapping + context
# and returns a list of findings.
# --------------------------------------------------------------------------- #

def check_hsts(h, is_https: bool) -> list[Finding]:
    v = h.get("Strict-Transport-Security")
    if not is_https:
        return [Finding(
            "Strict-Transport-Security", "high", "Site served over plain HTTP",
            "Without TLS, anyone on the network path (Wi-Fi, ISP, proxy) can read and "
            "modify traffic. HSTS is ignored over HTTP, so it can't help until HTTPS is in place.",
            "Serve the site over HTTPS, redirect HTTP to HTTPS, then add HSTS.",
        )]
    if not v:
        return [Finding(
            "Strict-Transport-Security", "medium", "HSTS missing",
            "Without HSTS, a user typing the bare domain makes a first request over HTTP that an "
            "attacker can intercept and downgrade (SSL stripping).",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )]
    out = []
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age == 0:
        out.append(Finding("Strict-Transport-Security", "medium", "HSTS max-age is 0 or missing",
                           "max-age=0 tells browsers to forget the HSTS policy, disabling it.",
                           "Set max-age to at least 15552000 (180 days).", v))
    elif max_age < 15552000:
        out.append(Finding("Strict-Transport-Security", "low", f"HSTS max-age is short ({max_age}s)",
                           "Short lifetimes let the policy expire between visits, reopening the "
                           "downgrade window.", "Use max-age of at least 15552000 (180 days).", v))
    if "includesubdomains" not in v.lower():
        out.append(Finding("Strict-Transport-Security", "low", "HSTS lacks includeSubDomains",
                           "Subdomains are not covered, so an attacker can use an HTTP subdomain to "
                           "set cookies for the parent domain.",
                           "Add includeSubDomains once all subdomains support HTTPS.", v))
    if "preload" not in v.lower():
        out.append(Finding("Strict-Transport-Security", "info", "HSTS not preload-ready",
                           "Preloading ships the policy inside browsers so even the very first visit "
                           "is protected.", "Consider 'preload' and submitting to hstspreload.org.", v))
    return out


def split_multi_csp(raw: str) -> list[str]:
    """Split comma-joined CSP headers back into individual policies.

    HTTP allows multiple CSP headers; requests joins them with ', '.
    A real directive never starts with a comma, so we split on commas
    that are followed by a known directive name.
    """
    known = {"default-src", "script-src", "style-src", "img-src", "connect-src",
             "font-src", "object-src", "media-src", "frame-src", "child-src",
             "worker-src", "frame-ancestors", "form-action", "base-uri",
             "manifest-src", "navigate-to", "report-uri", "report-to",
             "require-trusted-types-for", "trusted-types", "sandbox",
             "upgrade-insecure-requests", "block-all-mixed-content",
             "plugin-types", "prefetch-src"}
    parts = re.split(r",\s*", raw)
    policies: list[str] = [parts[0]]
    for part in parts[1:]:
        first_token = part.strip().split()[0].lower() if part.strip() else ""
        if first_token in known:
            policies.append(part)
        else:
            policies[-1] += ", " + part
    return policies


def check_csp(h, meta_csp: str | None = None) -> list[Finding]:
    v = h.get("Content-Security-Policy")
    ro = h.get("Content-Security-Policy-Report-Only")
    if not v and meta_csp:
        v = meta_csp
    if not v:
        if ro:
            return [Finding("Content-Security-Policy", "medium", "CSP is report-only",
                            "Report-Only logs violations but blocks nothing, so it gives no XSS "
                            "protection yet.", "Promote the policy to Content-Security-Policy once "
                            "reports are clean.", ro)]
        return [Finding("Content-Security-Policy", "medium", "CSP missing",
                        "CSP is the main browser-side defence against XSS: it restricts where "
                        "scripts, styles and frames can load from. Without it any injected <script> runs.",
                        "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; "
                        "frame-ancestors 'self'")]
    policies = split_multi_csp(v)
    out = []
    if len(policies) > 1:
        out.append(Finding("Content-Security-Policy", "info",
                           f"Multiple CSP policies detected ({len(policies)})",
                           "The server sent multiple CSP headers (or a comma-joined one). "
                           "Browsers apply all of them (intersection), so the strictest wins. "
                           "Only the first is analyzed here.",
                           "Consolidate into a single Content-Security-Policy header.", v[:200]))
    d = parse_csp(policies[0])
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        out.append(Finding("Content-Security-Policy", "high", "CSP has no script-src or default-src",
                           "With neither directive, scripts may load from anywhere; the policy "
                           "doesn't mitigate XSS.", "Add default-src 'self' (or a strict script-src).", v))
    else:
        has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not (has_nonce_or_hash or strict_dynamic):
            out.append(Finding("Content-Security-Policy", "high", "script-src allows 'unsafe-inline'",
                               "Inline scripts and event handlers are allowed, which is exactly what most "
                               "XSS payloads use, so this largely defeats CSP.",
                               "Use nonces or hashes for inline scripts and drop 'unsafe-inline'.", v))
        if "'unsafe-eval'" in script:
            out.append(Finding("Content-Security-Policy", "medium", "script-src allows 'unsafe-eval'",
                               "eval()/new Function() let attacker-controlled strings become code.",
                               "Refactor away from eval and remove 'unsafe-eval'.", v))
        wild = [t for t in script if t in ("*", "http:", "https:", "data:") or t.startswith("*.")]
        if wild and not strict_dynamic:
            out.append(Finding("Content-Security-Policy", "high",
                               f"script-src allows broad sources ({' '.join(wild)})",
                               "Any host (or data: URIs) can serve scripts, so an attacker just hosts "
                               "their payload elsewhere.", "List specific origins, or use nonces + "
                               "'strict-dynamic'.", v))
    if "object-src" not in d and "default-src" not in d:
        out.append(Finding("Content-Security-Policy", "low", "CSP missing object-src",
                           "Plugins (<object>/<embed>) can be abused to run script.",
                           "Add object-src 'none'.", v))
    if "base-uri" not in d:
        out.append(Finding("Content-Security-Policy", "low", "CSP missing base-uri",
                           "An injected <base href> can redirect every relative script URL to an "
                           "attacker's server. base-uri does not fall back to default-src.",
                           "Add base-uri 'self' (or 'none').", v))
    if "frame-ancestors" not in d:
        out.append(Finding("Content-Security-Policy", "info", "CSP missing frame-ancestors",
                           "frame-ancestors is the modern clickjacking control (it does not fall back "
                           "to default-src).", "Add frame-ancestors 'self' (or 'none').", v))
    return out


def check_xfo(h, meta_csp: str | None = None) -> list[Finding]:
    raw_csp = h.get("Content-Security-Policy") or meta_csp or ""
    policies = split_multi_csp(raw_csp) if raw_csp else []
    csp = parse_csp(policies[0]) if policies else {}
    v = h.get("X-Frame-Options")
    if not v:
        if "frame-ancestors" in csp:
            return []
        return [Finding("X-Frame-Options", "medium", "Clickjacking protection missing",
                        "Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can "
                        "load this page in an invisible iframe and trick users into clicking it.",
                        "X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.")]
    val = v.strip().upper()
    if val.startswith("ALLOW-FROM"):
        return [Finding("X-Frame-Options", "medium", "X-Frame-Options uses ALLOW-FROM",
                        "ALLOW-FROM is not supported by modern browsers, which then ignore the header "
                        "entirely.", "Use CSP frame-ancestors <origin> instead.", v)]
    if val not in ("DENY", "SAMEORIGIN"):
        return [Finding("X-Frame-Options", "medium", "X-Frame-Options has an invalid value",
                        "Browsers ignore unrecognised values, leaving the page frameable.",
                        "Use DENY or SAMEORIGIN.", v)]
    return []


def check_xcto(h) -> list[Finding]:
    v = h.get("X-Content-Type-Options")
    if not v or v.strip().lower() != "nosniff":
        return [Finding("X-Content-Type-Options", "low",
                        "X-Content-Type-Options not 'nosniff'" if v else "X-Content-Type-Options missing",
                        "Browsers may 'sniff' content and execute an uploaded text/image file as "
                        "script or HTML.", "X-Content-Type-Options: nosniff", v)]
    return []


def check_referrer(h) -> list[Finding]:
    v = h.get("Referrer-Policy")
    if not v:
        return [Finding("Referrer-Policy", "low", "Referrer-Policy missing",
                        "Browsers default to strict-origin-when-cross-origin today, but setting it "
                        "explicitly avoids leaking full URLs (which may contain tokens) on older clients.",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    # The last valid token wins when multiple are listed.
    policy = [p.strip().lower() for p in v.split(",") if p.strip()][-1]
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return [Finding("Referrer-Policy", "medium", f"Referrer-Policy '{policy}' leaks full URLs",
                        "Full URLs, including paths and query strings, are sent to third-party sites.",
                        "Use strict-origin-when-cross-origin or no-referrer.", v)]
    return []


def check_permissions_policy(h) -> list[Finding]:
    if not h.get("Permissions-Policy") and not h.get("Feature-Policy"):
        return [Finding("Permissions-Policy", "info", "Permissions-Policy missing",
                        "Lets you switch off powerful features (camera, geolocation, payment) for the "
                        "page and its iframes, limiting what injected or third-party code can use.",
                        "Permissions-Policy: camera=(), microphone=(), geolocation=()")]
    return []


def check_xss_protection(h) -> list[Finding]:
    v = h.get("X-XSS-Protection")
    if v and v.strip().startswith("1"):
        return [Finding("X-XSS-Protection", "info", "Legacy X-XSS-Protection enabled",
                        "The old XSS auditor was removed from browsers and itself introduced "
                        "information-leak bugs. Modern guidance is to disable it and rely on CSP.",
                        "X-XSS-Protection: 0 (or remove it).", v)]
    return []


def check_disclosure(h) -> list[Finding]:
    out = []
    server = h.get("Server")
    if server and re.search(r"\d", server):
        out.append(Finding("Server", "low", "Server header discloses version",
                           "Exact versions let attackers match the host against known CVEs "
                           "without probing.", "Strip the version (e.g. nginx: server_tokens off).", server))
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        if (v := h.get(name)):
            out.append(Finding(name, "low", f"{name} discloses technology",
                               "Advertises the framework/runtime (and often its version), making "
                               "targeted attacks easier.", f"Remove the {name} header.", v))
    return out


def check_cookies(set_cookies: list[str], is_https: bool) -> list[Finding]:
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
                 for a in raw.split(";")[1:]}
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            missing.append("SameSite")
        if missing:
            out.append(Finding("Set-Cookie", "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                               f"Cookie '{name}' missing {', '.join(missing)}",
                               "Secure keeps it off plain HTTP; HttpOnly hides it from JavaScript (so XSS "
                               "can't steal it); SameSite limits cross-site sending (CSRF).",
                               "Set Secure; HttpOnly; SameSite=Lax on session cookies "
                               "(HttpOnly may be omitted for cookies JS must read).", raw[:200]))
        if samesite == "none" and "secure" not in attrs:
            out.append(Finding("Set-Cookie", "low", f"Cookie '{name}' has SameSite=None without Secure",
                               "Browsers reject SameSite=None cookies that aren't Secure.",
                               "Add Secure.", raw[:200]))
    return out


def check_coop(h) -> list[Finding]:
    v = h.get("Cross-Origin-Opener-Policy")
    if not v:
        return [Finding("Cross-Origin-Opener-Policy", "info", "COOP missing",
                        "Without COOP, other windows opened from this site share a browsing context "
                        "group, which can leak information via side channels (e.g. Spectre).",
                        "Cross-Origin-Opener-Policy: same-origin")]
    return []


def check_coep(h) -> list[Finding]:
    v = h.get("Cross-Origin-Embedder-Policy")
    if not v:
        return [Finding("Cross-Origin-Embedder-Policy", "info", "COEP missing",
                        "Without COEP, cross-origin resources can be loaded without explicit opt-in, "
                        "and the page cannot use SharedArrayBuffer or high-resolution timers.",
                        "Cross-Origin-Embedder-Policy: require-corp")]
    return []


def check_corp(h) -> list[Finding]:
    v = h.get("Cross-Origin-Resource-Policy")
    if not v:
        return [Finding("Cross-Origin-Resource-Policy", "info", "CORP missing",
                        "Without CORP, other sites can embed this resource in img/script/iframe tags. "
                        "For same-site resources this leaks data to cross-origin pages.",
                        "Cross-Origin-Resource-Policy: same-origin (or same-site)")]
    return []


def check_host_cookie_prefix(set_cookies: list[str], is_https: bool) -> list[Finding]:
    if not is_https:
        return []
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        if not name.startswith("__Host-"):
            continue
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
                 for a in raw.split(";")[1:]}
        problems = []
        if "secure" not in attrs:
            problems.append("Secure")
        path_val = attrs.get("path", "").strip()
        if path_val != "/":
            problems.append("Path=/")
        if "domain" in attrs:
            problems.append("no Domain")
        if problems:
            out.append(Finding("Set-Cookie", "medium",
                               f"__Host- cookie '{name}' violates prefix rules ({', '.join(problems)} required)",
                               "__Host- cookies must have Secure, Path=/ and no Domain attribute. "
                               "Browsers reject cookies that break these rules, so the cookie is silently dropped.",
                               f"Set: {name}=...; Secure; Path=/  (and remove any Domain attribute).",
                               raw[:200]))
    return out


def check_cors(url: str, session: requests.Session, timeout: int) -> list[Finding]:
    """Send a request with a foreign Origin and see whether it is reflected."""
    probe_origin = "https://reconkit-cors-probe.example"
    try:
        r = session.get(url, headers={"Origin": probe_origin}, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return []
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao == probe_origin:
        return [Finding("Access-Control-Allow-Origin", "high" if acac else "medium",
                        "CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
                        "The server echoes back any Origin, so any website can read responses from "
                        "this endpoint" + (" using the victim's cookies." if acac else "."),
                        "Validate Origin against an explicit allowlist.", acao)]
    if acao == "null":
        return [Finding("Access-Control-Allow-Origin", "medium", "CORS allows the 'null' origin",
                        "Sandboxed iframes and file:// pages send Origin: null, so attackers can "
                        "trivially obtain it.", "Never allow 'null'.", acao)]
    if acao == "*":
        return [Finding("Access-Control-Allow-Origin", "info", "CORS allows any origin (*)",
                        "Fine for truly public data; browsers block '*' with credentials, but make sure "
                        "nothing sensitive is exposed without auth.", "", acao)]
    return []


def check_https_redirect(url: str, session: requests.Session, timeout: int,
                         max_hops: int = 5) -> list[Finding]:
    """Request the http:// version of the host and follow redirects by hand.

    HSTS only protects visits *after* the browser has seen it, so the plain-HTTP
    entry point must send users straight to HTTPS on the same host (that first
    HTTPS response is where the browser learns the HSTS policy).
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return []
    current = f"http://{parsed.netloc}/"
    hops: list[str] = []
    for _ in range(max_hops):
        try:
            r = session.get(current, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            return []  # port 80 closed or filtered: nothing served in plaintext
        location = r.headers.get("Location")
        if not (300 <= r.status_code < 400 and location):
            break
        nxt = urljoin(current, location)
        hops.append(nxt)
        if urlparse(nxt).scheme == "https":
            break
        current = nxt

    chain = " -> ".join([f"http://{parsed.netloc}/"] + hops)
    if not hops:
        return [Finding("Redirect", "medium", "HTTP does not redirect to HTTPS",
                        "The site answers over plain HTTP without redirecting, so users who type the "
                        "bare domain or follow an old http:// link stay on an unencrypted connection.",
                        "Return a 301 from http:// to the same URL on https://.", chain)]
    final = urlparse(hops[-1])
    if final.scheme != "https":
        return [Finding("Redirect", "medium", "HTTP redirect never reaches HTTPS",
                        f"After {len(hops)} redirect(s) the browser is still on plain HTTP.",
                        "Redirect http:// directly to https://.", chain)]
    if len(hops) > 1:
        return [Finding("Redirect", "low", "HTTP reaches HTTPS only via extra plain-HTTP hops",
                        "Every hop over plain HTTP is a chance for an attacker on the network to "
                        "rewrite the redirect and keep the user on HTTP.",
                        "Make the first response a redirect to https://.", chain)]
    if final.hostname != host:
        return [Finding("Redirect", "low", "First redirect goes to HTTPS on a different host",
                        f"http://{host} jumps straight to {final.hostname}, so the browser never sees "
                        f"an HTTPS response from {host} and can't learn its HSTS policy.",
                        f"Redirect to https://{host}/ first, then on to {final.hostname}.", chain)]
    return []


# --------------------------------------------------------------------------- #

def analyze_response(resp: requests.Response, url: str,
                     meta_csp: str | None = None) -> list[Finding]:
    h = resp.headers  # requests' CaseInsensitiveDict
    is_https = urlparse(resp.url).scheme == "https"
    findings: list[Finding] = []
    findings += check_hsts(h, is_https)
    findings += check_csp(h, meta_csp=meta_csp)
    findings += check_xfo(h, meta_csp=meta_csp)
    findings += check_xcto(h)
    findings += check_referrer(h)
    findings += check_permissions_policy(h)
    findings += check_xss_protection(h)
    findings += check_disclosure(h)
    cookies = get_set_cookies(resp)
    findings += check_cookies(cookies, is_https)
    findings += check_host_cookie_prefix(cookies, is_https)
    findings += check_coop(h)
    findings += check_coep(h)
    findings += check_corp(h)
    return findings


def analyze(url: str, *, session: requests.Session | None = None, timeout: int = DEFAULT_TIMEOUT,
            cors: bool = True, redirect: bool = True) -> HeaderReport:
    url = normalize_url(url)
    session = session or make_session()
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        msg = str(exc)
        tls_finding = Finding("TLS", "high", "TLS certificate error",
                              f"The TLS handshake failed: {msg[:200]}. This may indicate an expired, "
                              "self-signed, or misconfigured certificate.",
                              "Install a valid certificate from a trusted CA.")
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        except requests.RequestException:
            return HeaderReport(url=url, final_url=url, status=0,
                                headers={}, findings=[tls_finding],
                                score=max(0, 100 - SEVERITY_WEIGHT["high"]),
                                grade=grade_for(max(0, 100 - SEVERITY_WEIGHT["high"])))
        findings = analyze_response(resp, url)
        findings.insert(0, tls_finding)
        findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
        score = max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings))
        return HeaderReport(url=url, final_url=resp.url, status=resp.status_code,
                            headers=dict(resp.headers), findings=findings,
                            score=score, grade=grade_for(score))

    challenge = detect_challenge_page(resp)
    if challenge:
        return HeaderReport(
            url=url, final_url=resp.url, status=resp.status_code,
            headers=dict(resp.headers), findings=[], score=0,
            grade="!", blocked_by=challenge,
        )

    meta_csp = extract_meta_csp(resp.text[:200_000]) if resp.text else None
    findings = analyze_response(resp, url, meta_csp=meta_csp)
    if cors:
        findings += check_cors(resp.url, session, timeout)
    if redirect and urlparse(resp.url).scheme == "https":
        findings += check_https_redirect(resp.url, session, timeout)
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    score = max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    return HeaderReport(url=url, final_url=resp.url, status=resp.status_code,
                        headers=dict(resp.headers), findings=findings,
                        score=score, grade=grade_for(score), meta_csp=meta_csp)


def analyze_paths(base_url: str, paths: list[str], *,
                  session: requests.Session | None = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  cors: bool = True, redirect: bool = True) -> list[HeaderReport]:
    base_url = normalize_url(base_url)
    session = session or make_session()
    reports: list[HeaderReport] = []
    for path in paths:
        path = path if path.startswith("/") else "/" + path
        url = base_url.rstrip("/") + path
        try:
            reports.append(analyze(url, session=session, timeout=timeout,
                                   cors=cors, redirect=redirect))
        except requests.RequestException:
            continue
    return reports
