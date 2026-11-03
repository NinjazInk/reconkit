import dns.resolver
import requests
from requests.structures import CaseInsensitiveDict

from reconkit import headers as H
from reconkit import scan as SC
from reconkit import subdomains as S
from reconkit import takeover as T


def resp(status=200, headers=None, text="", url="https://example.com/"):
    r = requests.Response()
    r.status_code = status
    r.url = url
    r.headers = CaseInsensitiveDict(headers or {})
    r._content = text.encode()
    return r


class MapSession:
    """Fake session: url -> Response, or an exception to raise."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        out = self.routes.get(url)
        if out is None:
            raise requests.ConnectionError(url)
        if isinstance(out, Exception):
            raise out
        return out


# ---------------- HTTP -> HTTPS redirect ----------------

def redirect_titles(routes, url="https://example.com/"):
    return [f.title for f in H.check_https_redirect(url, MapSession(routes), 5)]


def test_redirect_ok():
    routes = {"http://example.com/": resp(301, {"Location": "https://example.com/"})}
    assert redirect_titles(routes) == []


def test_relative_redirect_ok():
    # Location may be relative; scheme change requires an absolute URL, so
    # a relative one keeps us on http and is followed.
    routes = {
        "http://example.com/": resp(302, {"Location": "/home"}),
        "http://example.com/home": resp(301, {"Location": "https://example.com/home"}),
    }
    assert redirect_titles(routes) == ["HTTP reaches HTTPS only via extra plain-HTTP hops"]


def test_no_redirect():
    routes = {"http://example.com/": resp(200)}
    assert redirect_titles(routes) == ["HTTP does not redirect to HTTPS"]


def test_redirect_stays_on_http():
    routes = {
        "http://example.com/": resp(301, {"Location": "http://www.example.com/"}),
        "http://www.example.com/": resp(200),
    }
    assert redirect_titles(routes) == ["HTTP redirect never reaches HTTPS"]


def test_redirect_to_other_host():
    routes = {"http://example.com/": resp(301, {"Location": "https://www.example.com/"})}
    assert redirect_titles(routes) == ["First redirect goes to HTTPS on a different host"]


def test_port_80_closed_is_fine():
    assert redirect_titles({}) == []


# ---------------- Dangling CNAME resolution ----------------

class Rdata:
    def __init__(self, target):
        self.target = dns.name.from_text(target)


def test_resolver_detects_dangling_cname(monkeypatch):
    r = S.Resolver()

    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            return [Rdata("gone-bucket.s3.amazonaws.com.")]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(r._r, "resolve", fake_resolve)
    res = r.resolve("assets.example.com")
    assert res.dangling and res.cnames == ["gone-bucket.s3.amazonaws.com"]
    assert res.alive  # still reported, so it isn't silently dropped


def test_resolver_plain_nxdomain(monkeypatch):
    r = S.Resolver()

    def fake_resolve(name, rtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(r._r, "resolve", fake_resolve)
    res = r.resolve("nope.example.com")
    assert not res.dangling and not res.alive


# ---------------- Takeover checks ----------------

def test_takeover_dangling_known_service():
    res = S.Resolution("shop.example.com", [], ["old.myshopify.com"], dangling=True)
    f = T.check(res, MapSession({}))
    assert f.confidence == "likely" and f.service == "Shopify"


def test_takeover_dangling_unknown_service():
    res = S.Resolution("x.example.com", [], ["host.some-cdn.example"], dangling=True)
    f = T.check(res, MapSession({}))
    assert f.confidence == "possible" and f.service is None


def test_takeover_fingerprint():
    res = S.Resolution("docs.example.com", ["185.199.108.153"], ["acme.github.io"])
    session = MapSession({"http://docs.example.com/":
                          resp(404, text="<h1>404</h1> There isn't a GitHub Pages site here.")})
    f = T.check(res, session)
    assert f and f.service == "GitHub Pages" and "error text" in f.evidence[0]


def test_takeover_claimed_resource_is_clean():
    res = S.Resolution("docs.example.com", ["185.199.108.153"], ["acme.github.io"])
    session = MapSession({"http://docs.example.com/": resp(200, text="Welcome to Acme docs")})
    assert T.check(res, session) is None


def test_no_cname_no_check():
    assert T.check(S.Resolution("a.example.com", ["1.2.3.4"]), MapSession({})) is None


# ---------------- Scan pipeline ----------------

def test_scan_orders_and_combines(monkeypatch):
    fake = S.SubdomainResult("example.com")
    for n in ("good.example.com", "bad.example.com", "gone.example.com", "dead.example.com"):
        fake.add(n, "crtsh")
    fake.resolved = {
        "good.example.com": S.Resolution("good.example.com", ["1.1.1.1"]),
        "bad.example.com": S.Resolution("bad.example.com", ["2.2.2.2"]),
        "gone.example.com": S.Resolution("gone.example.com", [], ["x.herokuapp.com"], dangling=True),
        "dead.example.com": S.Resolution("dead.example.com"),  # no records: skipped
    }
    monkeypatch.setattr(SC, "enumerate_subdomains", lambda *a, **kw: fake)

    def fake_analyze(url, **kw):
        score = 95 if "good" in url else 30
        return H.HeaderReport(url, url, 200, {}, [], score, H.grade_for(score), blocked_by=None)
    monkeypatch.setattr(SC, "analyze", fake_analyze)

    result = SC.scan("example.com", http_threads=2)
    names = [h.name for h in result.hosts]
    assert names == ["gone.example.com", "bad.example.com", "good.example.com"]
    assert result.takeovers[0].service == "Heroku"
    assert result.hosts[0].report is None  # dangling: no HTTP audit
    assert result.to_dict()["hosts"][1]["grade"] == "F"
