"""Dangling-CNAME (subdomain takeover) detection.

A subdomain takeover happens when ``shop.example.com`` is a CNAME to a hosted
service (``example.myshopify.com``, ``example.github.io``, an S3 bucket ...)
but the resource on that service has been deleted. Anyone who signs up and
claims the same resource name then serves content on ``shop.example.com``:
phishing, cookie theft for the parent domain, and so on.

Detection uses two signals:

* the CNAME target no longer resolves (NXDOMAIN), or
* the service answers with its "nothing configured here" page.

This module only *detects*. Findings are leads that need manual confirmation:
providers change their error pages and some resources can't be re-registered.
The community list at github.com/EdOverflow/can-i-take-over-xyz tracks which
services are currently exploitable.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

import requests

from .subdomains import Resolution

SERVICES: list[dict] = [
    {"service": "GitHub Pages", "cname": [r"\.github\.io$"],
     "fingerprint": ["There isn't a GitHub Pages site here"]},
    {"service": "Heroku", "cname": [r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.herokussl\.com$"],
     "fingerprint": ["No such app", "no-such-app.html"]},
    {"service": "AWS S3", "cname": [r"\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$", r"\.s3-website[.-]"],
     "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "AWS Elastic Beanstalk", "cname": [r"\.elasticbeanstalk\.com$"], "fingerprint": []},
    {"service": "Microsoft Azure",
     "cname": [r"\.azurewebsites\.net$", r"\.cloudapp\.net$", r"\.cloudapp\.azure\.com$",
               r"\.trafficmanager\.net$", r"\.blob\.core\.windows\.net$", r"\.azureedge\.net$"],
     "fingerprint": []},
    {"service": "Shopify", "cname": [r"\.myshopify\.com$"],
     "fingerprint": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly", "cname": [r"\.fastly\.net$"], "fingerprint": ["Fastly error: unknown domain"]},
    {"service": "Netlify", "cname": [r"\.netlify\.(app|com)$"], "fingerprint": ["Not Found - Request ID"]},
    {"service": "Pantheon", "cname": [r"\.pantheonsite\.io$"], "fingerprint": ["404 error unknown site"]},
    {"service": "Zendesk", "cname": [r"\.zendesk\.com$"], "fingerprint": ["Help Center Closed"]},
    {"service": "Surge.sh", "cname": [r"\.surge\.sh$"], "fingerprint": ["project not found"]},
    {"service": "Bitbucket", "cname": [r"\.bitbucket\.io$"], "fingerprint": ["Repository not found"]},
    {"service": "Tumblr", "cname": [r"\.tumblr\.com$"],
     "fingerprint": ["Whatever you were looking for doesn't currently exist at this address"]},
    {"service": "Ghost", "cname": [r"\.ghost\.io$"],
     "fingerprint": ["The thing you were looking for is no longer here"]},
    {"service": "Read the Docs", "cname": [r"\.readthedocs\.io$"],
     "fingerprint": ["unknown to Read the Docs"]},
]


@dataclass
class TakeoverFinding:
    name: str
    cnames: list[str]
    service: str | None
    confidence: str  # "likely" | "possible"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def match_service(cnames: list[str]) -> dict | None:
    for target in cnames:
        for svc in SERVICES:
            if any(re.search(p, target, re.I) for p in svc["cname"]):
                return svc
    return None


def fetch_body(name: str, session: requests.Session, timeout: int) -> str | None:
    """Fetch the subdomain itself. Plain HTTP first: on a dangling host the TLS
    certificate usually won't match, and we only need the error page text."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{name}/", timeout=timeout, allow_redirects=True)
            return r.text[:200_000]
        except requests.RequestException:
            continue
    return None


def check(res: Resolution, session: requests.Session, timeout: int = 10) -> TakeoverFinding | None:
    if not res.cnames:
        return None
    svc = match_service(res.cnames)
    evidence: list[str] = []
    if res.dangling:
        evidence.append(f"CNAME target {res.cnames[-1]} does not resolve (NXDOMAIN)")
    if svc and svc["fingerprint"] and not res.dangling:
        body = fetch_body(res.name, session, timeout)
        if body:
            for fp in svc["fingerprint"]:
                if fp.lower() in body.lower():
                    evidence.append(f"response contains {svc['service']} error text: {fp!r}")
                    break
    if not evidence:
        return None
    confidence = "likely" if svc else "possible"
    return TakeoverFinding(res.name, list(res.cnames), svc["service"] if svc else None,
                           confidence, evidence)
