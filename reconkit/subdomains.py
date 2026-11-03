"""Subdomain enumeration.

Two families of technique:

* Passive  - ask third parties who have already seen the names. Certificate
  Transparency (CT) logs are the big one: every publicly-trusted TLS cert is
  logged, and certs list the hostnames they cover. You never touch the target.
* Active   - guess names (``www``, ``api``, ``dev`` ...) and ask DNS whether they
  exist. This hits the target's authoritative nameservers.

Wildcard DNS (``*.example.com`` resolving to something) makes every guess look
valid, so we detect it first by resolving a few random labels and discard
brute-force hits that resolve to exactly the wildcard answer.
"""
from __future__ import annotations

import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from importlib import resources
from typing import Callable, Iterable

import requests

from .http import DEFAULT_TIMEOUT, make_session

try:  # dnspython gives us CNAMEs, AAAA and control over timeouts
    import dns.exception
    import dns.resolver

    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover - fallback path
    import socket

    HAVE_DNSPYTHON = False

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


@dataclass
class Resolution:
    name: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    # True when the name has a CNAME but the chain ends in NXDOMAIN: the alias
    # points at something that no longer exists (a subdomain-takeover signal).
    dangling: bool = False

    @property
    def alive(self) -> bool:
        return bool(self.addresses or self.cnames)


@dataclass
class SubdomainResult:
    domain: str
    found: dict[str, set[str]] = field(default_factory=dict)  # name -> sources
    resolved: dict[str, Resolution] = field(default_factory=dict)
    wildcard_ips: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    def add(self, name: str, source: str) -> None:
        self.found.setdefault(name, set()).add(source)

    def to_dict(self) -> dict:
        out = []
        for name in sorted(self.found):
            r = self.resolved.get(name)
            out.append({
                "name": name,
                "sources": sorted(self.found[name]),
                "addresses": r.addresses if r else None,
                "cnames": r.cnames if r else None,
                "dangling": r.dangling if r else None,
            })
        return {
            "domain": self.domain,
            "wildcard_ips": sorted(self.wildcard_ips),
            "subdomains": out,
            "errors": self.errors,
        }


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"not a valid domain name: {domain!r}")
    return domain


def clean_name(name: str, domain: str) -> str | None:
    """Normalise a candidate name; return None if it isn't under ``domain``."""
    name = name.strip().lower().rstrip(".")
    while name.startswith("*."):
        name = name[2:]
    if not name or " " in name or "@" in name:
        return None
    if name == domain or name.endswith("." + domain):
        return name
    return None


# --------------------------------------------------------------------------- #
# Passive sources
# --------------------------------------------------------------------------- #

def from_crtsh(domain: str, session: requests.Session, timeout: int = 45) -> set[str]:
    """Certificate Transparency search via crt.sh (``%`` is a SQL wildcard)."""
    resp = session.get(
        "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout
    )
    resp.raise_for_status()
    names: set[str] = set()
    for entry in resp.json():
        for field_ in ("name_value", "common_name"):
            for raw in str(entry.get(field_, "")).splitlines():
                if (n := clean_name(raw, domain)):
                    names.add(n)
    return names


def from_certspotter(domain: str, session: requests.Session, timeout: int = DEFAULT_TIMEOUT) -> set[str]:
    """Another CT log aggregator (free tier is rate limited)."""
    resp = session.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=timeout,
    )
    resp.raise_for_status()
    names: set[str] = set()
    for issuance in resp.json():
        for raw in issuance.get("dns_names", []):
            if (n := clean_name(raw, domain)):
                names.add(n)
    return names


def from_hackertarget(domain: str, session: requests.Session, timeout: int = DEFAULT_TIMEOUT) -> set[str]:
    """Passive DNS dataset. Returns CSV lines 'host,ip'."""
    resp = session.get(
        "https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=timeout
    )
    resp.raise_for_status()
    if "API count exceeded" in resp.text or resp.text.startswith("error"):
        raise RuntimeError(resp.text.strip()[:120])
    names: set[str] = set()
    for line in resp.text.splitlines():
        if (n := clean_name(line.split(",", 1)[0], domain)):
            names.add(n)
    return names


PASSIVE_SOURCES: dict[str, Callable[[str, requests.Session], set[str]]] = {
    "crtsh": from_crtsh,
    "certspotter": from_certspotter,
    "hackertarget": from_hackertarget,
}


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

class Resolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 3.0):
        self.timeout = timeout
        if HAVE_DNSPYTHON:
            self._r = dns.resolver.Resolver()
            if nameservers:
                self._r.nameservers = nameservers
            self._r.timeout = timeout
            self._r.lifetime = timeout * 2

    def resolve(self, name: str) -> Resolution:
        res = Resolution(name)
        if not HAVE_DNSPYTHON:  # pragma: no cover
            try:
                infos = socket.getaddrinfo(name, None)
                res.addresses = sorted({i[4][0] for i in infos})
            except OSError:
                pass
            return res
        for rtype in ("A", "AAAA"):
            try:
                answer = self._r.resolve(name, rtype)
            except dns.resolver.NXDOMAIN:
                # Either the name doesn't exist, or it's a CNAME whose target
                # doesn't. Ask for the CNAME itself (servers answer that without
                # following the chain) to tell the two apart.
                self._check_dangling(name, res)
                return res
            except dns.resolver.NoNameservers:
                return res
            except (dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            for rrset in answer.response.answer:
                for rdata in rrset:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        target = rdata.target.to_text().rstrip(".")
                        if target not in res.cnames:
                            res.cnames.append(target)
                    elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        res.addresses.append(rdata.address)
        res.addresses = sorted(set(res.addresses))
        return res

    def _check_dangling(self, name: str, res: Resolution) -> None:
        try:
            answer = self._r.resolve(name, "CNAME")
        except dns.exception.DNSException:
            return
        for rdata in answer:
            res.cnames.append(rdata.target.to_text().rstrip("."))
        res.dangling = bool(res.cnames)


def detect_wildcard(domain: str, resolver: Resolver, probes: int = 3) -> set[str]:
    """Resolve random labels; any answers mean a wildcard record exists."""
    ips: set[str] = set()
    for _ in range(probes):
        label = "rk-" + secrets.token_hex(8)
        r = resolver.resolve(f"{label}.{domain}")
        ips.update(r.addresses)
    return ips


def load_wordlist(path: str | None = None) -> list[str]:
    if path:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    else:
        text = resources.files("reconkit.data").joinpath("subdomains.txt").read_text()
    words = []
    seen = set()
    for line in text.splitlines():
        w = line.strip().lower()
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            words.append(w)
    return words


def resolve_many(names: Iterable[str], resolver: Resolver, threads: int,
                 on_result: Callable[[Resolution], None] | None = None) -> dict[str, Resolution]:
    out: dict[str, Resolution] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolver.resolve, n): n for n in names}
        for fut in as_completed(futures):
            r = fut.result()
            out[r.name] = r
            if on_result:
                on_result(r)
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def enumerate_subdomains(
    domain: str,
    *,
    passive: bool = True,
    sources: list[str] | None = None,
    bruteforce: bool = False,
    wordlist: str | None = None,
    resolve: bool = True,
    threads: int = 50,
    nameservers: list[str] | None = None,
    session: requests.Session | None = None,
    resolver: Resolver | None = None,
    log: Callable[[str], None] = lambda _m: None,
) -> SubdomainResult:
    domain = validate_domain(domain)
    session = session or make_session()
    resolver = resolver or Resolver(nameservers)
    result = SubdomainResult(domain)

    if passive:
        for name in sources or list(PASSIVE_SOURCES):
            fn = PASSIVE_SOURCES[name]
            log(f"[passive] querying {name} ...")
            try:
                hits = fn(domain, session)
            except Exception as exc:  # network errors, rate limits, bad JSON
                msg = f"{name}: {type(exc).__name__}: {exc}"
                result.errors.append(msg)
                log(f"[passive] {msg}")
                continue
            log(f"[passive] {name}: {len(hits)} names")
            for h in hits:
                result.add(h, name)

    if bruteforce:
        result.wildcard_ips = detect_wildcard(domain, resolver)
        if result.wildcard_ips:
            log(f"[brute] wildcard DNS detected -> {', '.join(sorted(result.wildcard_ips))}")
        words = load_wordlist(wordlist)
        candidates = [f"{w}.{domain}" for w in words]
        log(f"[brute] trying {len(candidates)} names with {threads} threads ...")
        resolved = resolve_many(candidates, resolver, threads)
        for name, r in resolved.items():
            if not r.alive:
                continue
            if result.wildcard_ips and set(r.addresses) <= result.wildcard_ips and not r.cnames:
                continue  # just the wildcard answering
            result.add(name, "bruteforce")
            result.resolved[name] = r

    if resolve:
        todo = [n for n in result.found if n not in result.resolved]
        if todo:
            log(f"[dns] resolving {len(todo)} passive results ...")
            result.resolved.update(resolve_many(todo, resolver, threads))

    return result
