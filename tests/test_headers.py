import requests
from requests.structures import CaseInsensitiveDict

from reconkit import headers as H


def make_resp(hdrs: dict, url="https://example.com/", cookies=None):
    r = requests.Response()
    r.status_code = 200
    r.url = url
    r.headers = CaseInsensitiveDict(hdrs)
    if cookies:
        r.headers["Set-Cookie"] = ", ".join(cookies)

        class Raw:
            class headers:
                @staticmethod
                def getlist(_name):
                    return cookies
        r.raw = Raw()
    return r


def titles(findings):
    return [f.title for f in findings]


GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def test_well_configured_site_has_no_findings():
    assert H.analyze_response(make_resp(GOOD), "https://example.com/") == []


def test_empty_headers_flag_the_basics():
    t = titles(H.analyze_response(make_resp({}), "https://example.com/"))
    assert "HSTS missing" in t
    assert "CSP missing" in t
    assert "Clickjacking protection missing" in t
    assert "X-Content-Type-Options missing" in t


def test_plain_http_is_high():
    f = H.check_hsts(CaseInsensitiveDict(), is_https=False)
    assert f[0].severity == "high"


def test_short_hsts():
    f = H.check_hsts(CaseInsensitiveDict({"Strict-Transport-Security": "max-age=600"}), True)
    assert any("short" in x.title for x in f)


def test_csp_unsafe_inline_and_wildcard():
    h = CaseInsensitiveDict({"Content-Security-Policy": "script-src 'self' 'unsafe-inline' *"})
    t = titles(H.check_csp(h))
    assert "script-src allows 'unsafe-inline'" in t
    assert any(x.startswith("script-src allows broad sources") for x in t)


def test_csp_unsafe_inline_ok_with_nonce():
    h = CaseInsensitiveDict({"Content-Security-Policy":
                             "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'"})
    assert "script-src allows 'unsafe-inline'" not in titles(H.check_csp(h))


def test_csp_report_only():
    h = CaseInsensitiveDict({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    assert titles(H.check_csp(h)) == ["CSP is report-only"]


def test_frame_ancestors_satisfies_clickjacking():
    h = CaseInsensitiveDict({"Content-Security-Policy": "frame-ancestors 'self'"})
    assert H.check_xfo(h) == []


def test_xfo_allow_from():
    h = CaseInsensitiveDict({"X-Frame-Options": "ALLOW-FROM https://a.example"})
    assert "ALLOW-FROM" in H.check_xfo(h)[0].title


def test_referrer_unsafe():
    h = CaseInsensitiveDict({"Referrer-Policy": "no-referrer, unsafe-url"})
    assert H.check_referrer(h)[0].severity == "medium"


def test_version_disclosure():
    h = CaseInsensitiveDict({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"})
    assert len(H.check_disclosure(h)) == 2
    assert H.check_disclosure(CaseInsensitiveDict({"Server": "nginx"})) == []


def test_cookie_flags():
    f = H.check_cookies(["sid=abc; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"], is_https=True)
    assert len(f) == 1
    assert "Secure, HttpOnly, SameSite" in f[0].title


def test_cookies_read_from_raw_headers():
    resp = make_resp(GOOD, cookies=["a=1; Path=/", "b=2; Secure; HttpOnly; SameSite=Strict"])
    t = titles(H.analyze_response(resp, resp.url))
    assert t == ["Cookie 'a' missing Secure, HttpOnly, SameSite"]


def test_grade():
    assert H.grade_for(100) == "A"
    assert H.grade_for(70) == "C"
    assert H.grade_for(0) == "F"


def test_cors_reflection(monkeypatch):
    class FakeSession:
        def get(self, url, headers=None, **kw):
            return make_resp({"Access-Control-Allow-Origin": headers["Origin"],
                              "Access-Control-Allow-Credentials": "true"})
    f = H.check_cors("https://example.com/", FakeSession(), 5)
    assert f[0].severity == "high"


# ---------------- Meta CSP ----------------

def test_extract_meta_csp():
    html = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>'
    assert H.extract_meta_csp(html) == "default-src 'self'"


def test_extract_meta_csp_reversed_attrs():
    html = "<meta content=\"script-src 'none'\" http-equiv=\"Content-Security-Policy\">"
    assert H.extract_meta_csp(html) == "script-src 'none'"


def test_extract_meta_csp_returns_none():
    assert H.extract_meta_csp("<html><head></head></html>") is None


def test_meta_csp_used_when_header_missing():
    resp = make_resp({})
    findings = H.analyze_response(resp, "https://example.com/",
                                  meta_csp="default-src 'self'; object-src 'none'; base-uri 'none'")
    t = titles(findings)
    assert "CSP missing" not in t


# ---------------- Challenge page detection ----------------

def test_detect_challenge_cloudflare():
    r = make_resp({})
    r.status_code = 503
    r._content = b'<html><head><title>Just a moment...</title></head><body>challenge</body></html>'
    assert H.detect_challenge_page(r) == "Cloudflare"


def test_detect_challenge_cf_header():
    r = make_resp({"cf-mitigated": "challenge"})
    r.status_code = 200
    r._content = b''
    assert H.detect_challenge_page(r) == "Cloudflare"


def test_no_challenge_normal_page():
    r = make_resp({})
    r.status_code = 200
    r._content = b'<html><body>Hello world</body></html>'
    assert H.detect_challenge_page(r) is None


def test_challenge_page_not_graded():
    r = make_resp({})
    r.status_code = 403
    r._content = b'<html><title>Attention Required! | Cloudflare</title></html>'

    class FakeSession:
        def get(self, url, **kw):
            return r

    report = H.analyze("https://example.com", session=FakeSession())
    assert report.blocked_by == "Cloudflare"
    assert report.grade == "!"
    assert report.findings == []
