import pytest

from reconkit import subdomains as S


class FakeResp:
    def __init__(self, json_data=None, text=""):
        self._json = json_data
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, resp):
        self.resp = resp

    def get(self, *a, **kw):
        return self.resp


class FakeResolver:
    """Maps names to IPs; '*' entry simulates wildcard DNS."""

    def __init__(self, table):
        self.table = table

    def resolve(self, name):
        if name in self.table:
            return S.Resolution(name, list(self.table[name]))
        if "*" in self.table:
            return S.Resolution(name, list(self.table["*"]))
        return S.Resolution(name)


def test_validate_domain():
    assert S.validate_domain(" Example.COM. ") == "example.com"
    assert S.validate_domain("*.example.com") == "example.com"
    for bad in ("localhost", "exa mple.com", "-a.com", "http://example.com"):
        with pytest.raises(ValueError):
            S.validate_domain(bad)


def test_clean_name():
    assert S.clean_name("*.API.example.com.", "example.com") == "api.example.com"
    assert S.clean_name("example.com", "example.com") == "example.com"
    assert S.clean_name("notexample.com", "example.com") is None
    assert S.clean_name("admin@example.com", "example.com") is None


def test_crtsh_parsing():
    data = [
        {"name_value": "www.example.com\n*.dev.example.com", "common_name": "example.com"},
        {"name_value": "evil.com", "common_name": "mail.example.com"},
    ]
    names = S.from_crtsh("example.com", FakeSession(FakeResp(data)))
    assert names == {"www.example.com", "dev.example.com", "example.com", "mail.example.com"}


def test_hackertarget_parsing():
    text = "www.example.com,1.2.3.4\nmail.example.com,1.2.3.5\n"
    names = S.from_hackertarget("example.com", FakeSession(FakeResp(text=text)))
    assert names == {"www.example.com", "mail.example.com"}


def test_hackertarget_rate_limit():
    with pytest.raises(RuntimeError):
        S.from_hackertarget("example.com", FakeSession(FakeResp(text="API count exceeded")))


def test_bruteforce_filters_wildcard(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("www\napi\nnothere\n")
    resolver = FakeResolver({"*": ["9.9.9.9"], "www.example.com": ["1.1.1.1"]})
    r = S.enumerate_subdomains("example.com", passive=False, bruteforce=True,
                               wordlist=str(wl), resolver=resolver, threads=2)
    assert r.wildcard_ips == {"9.9.9.9"}
    assert set(r.found) == {"www.example.com"}


def test_bruteforce_without_wildcard(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("www\napi\nnothere\n")
    resolver = FakeResolver({"www.example.com": ["1.1.1.1"], "api.example.com": ["2.2.2.2"]})
    r = S.enumerate_subdomains("example.com", passive=False, bruteforce=True,
                               wordlist=str(wl), resolver=resolver, threads=2)
    assert set(r.found) == {"www.example.com", "api.example.com"}


def test_passive_errors_are_collected(monkeypatch):
    def boom(domain, session):
        raise ConnectionError("down")
    monkeypatch.setitem(S.PASSIVE_SOURCES, "crtsh", boom)
    monkeypatch.setitem(S.PASSIVE_SOURCES, "hackertarget", lambda d, s: {"a.example.com"})
    r = S.enumerate_subdomains("example.com", sources=["crtsh", "hackertarget"],
                               resolver=FakeResolver({}), session=object())
    assert "a.example.com" in r.found
    assert r.errors and "crtsh" in r.errors[0]
    assert r.to_dict()["subdomains"][0]["addresses"] == []


def test_builtin_wordlist_loads():
    words = S.load_wordlist()
    assert "www" in words and len(words) == len(set(words))


# ---------------- Wildcard CNAME filtering ----------------

class CnameFakeResolver:
    """Returns a CNAME for wildcard, distinct record for real hosts."""

    def __init__(self, real_hosts):
        self.real_hosts = real_hosts

    def resolve(self, name):
        if name in self.real_hosts:
            return S.Resolution(name, self.real_hosts[name]["ips"],
                                self.real_hosts[name].get("cnames", []))
        return S.Resolution(name, ["10.0.0.1"], ["cdn-catchall.example.net"])


def test_wildcard_cname_filtering(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("www\napi\nghost\n")
    resolver = CnameFakeResolver({
        "www.example.com": {"ips": ["1.1.1.1"], "cnames": ["www-real.example.net"]},
        "api.example.com": {"ips": ["2.2.2.2"], "cnames": []},
    })
    r = S.enumerate_subdomains("example.com", passive=False, bruteforce=True,
                               wordlist=str(wl), resolver=resolver, threads=2)
    assert "www.example.com" in r.found
    assert "api.example.com" in r.found
    assert "ghost.example.com" not in r.found
    assert "cdn-catchall.example.net" in r.wildcard_cnames


def test_wildcard_signature_matches():
    sig = S.WildcardSignature(ips={"10.0.0.1"}, cnames={"cdn.example.net"})
    assert sig.matches(S.Resolution("a.example.com", ["10.0.0.1"]))
    assert sig.matches(S.Resolution("b.example.com", ["99.99.99.99"], ["cdn.example.net"]))
    assert not sig.matches(S.Resolution("c.example.com", ["1.2.3.4"], ["other.example.net"]))
    assert not sig.matches(S.Resolution("d.example.com", []))


# ---------------- SERVFAIL retry ----------------

def test_resolver_retries_servfail(monkeypatch):
    import dns.resolver
    r = S.Resolver()
    calls = []

    def fake_resolve(name, rtype):
        calls.append((name, rtype))
        raise dns.resolver.NoNameservers("SERVFAIL")

    monkeypatch.setattr(r._r, "resolve", fake_resolve)
    res = r.resolve("fail.example.com")
    assert res.error and "SERVFAIL" in res.error
    assert len(calls) >= 3  # 1 original + 2 retries for the first rtype


def test_resolver_servfail_succeeds_on_retry(monkeypatch):
    import dns.resolver as dr
    import dns.rdatatype
    r = S.Resolver()
    attempt = [0]

    class FakeAnswer:
        class response:
            answer = []

    def fake_resolve(name, rtype):
        attempt[0] += 1
        if attempt[0] <= 1:
            raise dr.NoNameservers("SERVFAIL")
        return FakeAnswer()

    monkeypatch.setattr(r._r, "resolve", fake_resolve)
    res = r.resolve("retry.example.com")
    assert res.error is None
