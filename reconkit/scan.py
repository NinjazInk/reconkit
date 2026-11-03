"""Attack-surface scan: enumerate subdomains, then audit every live one.

Forgotten hosts (old staging sites, abandoned marketing pages) are where weak
configuration and takeover-able CNAMEs tend to live, so checking only the main
site misses most of the interesting findings.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

import requests

from . import takeover as T
from .headers import HeaderReport, analyze, analyze_paths
from .http import make_session
from .subdomains import Resolution, SubdomainResult, enumerate_subdomains


@dataclass
class HostResult:
    name: str
    report: HeaderReport | None = None
    error: str | None = None
    takeover: T.TakeoverFinding | None = None
    path_reports: list[HeaderReport] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        if self.report:
            for f in self.report.findings:
                if f.severity in out:
                    out[f.severity] += 1
        return out

    def to_dict(self) -> dict:
        r = self.report
        d = {
            "name": self.name,
            "url": r.final_url if r else None,
            "status": r.status if r else None,
            "grade": r.grade if r else None,
            "score": r.score if r else None,
            "counts": self.counts(),
            "findings": r.to_dict()["findings"] if r else [],
            "error": self.error,
            "takeover": self.takeover.to_dict() if self.takeover else None,
        }
        if self.path_reports:
            d["paths"] = [pr.to_dict() for pr in self.path_reports]
        return d


@dataclass
class ScanResult:
    domain: str
    subdomains: SubdomainResult
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def takeovers(self) -> list[T.TakeoverFinding]:
        return [h.takeover for h in self.hosts if h.takeover]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains.to_dict(),
            "hosts": [h.to_dict() for h in self.hosts],
        }


def audit_host(res: Resolution, *, timeout: int, cors: bool,
               check_takeover: bool, extra_paths: list[str] | None = None) -> HostResult:
    session = make_session()  # one per thread: requests.Session isn't thread-safe
    out = HostResult(res.name)
    if check_takeover:
        try:
            out.takeover = T.check(res, session, timeout)
        except Exception as exc:  # never let one host kill the scan
            out.error = f"takeover check failed: {exc}"
    if res.dangling or not res.addresses:
        out.error = out.error or "no address (CNAME target does not resolve)"
        return out
    last_exc: Exception | None = None
    base_url: str | None = None
    for scheme in ("https", "http"):
        try:
            out.report = analyze(f"{scheme}://{res.name}", session=session, timeout=timeout, cors=cors)
            base_url = f"{scheme}://{res.name}"
            break
        except requests.RequestException as exc:
            last_exc = exc
    if not out.report:
        out.error = f"no HTTP(S) response ({type(last_exc).__name__})"
        return out
    if extra_paths and base_url:
        out.path_reports = analyze_paths(base_url, extra_paths, session=session,
                                         timeout=timeout, cors=cors, redirect=False)
    return out


def sort_key(h: HostResult):
    # Takeovers first, then worst grade, then hosts that didn't answer.
    return (h.takeover is None, h.report is None, h.report.score if h.report else 0, h.name)


def scan(
    domain: str,
    *,
    http_threads: int = 10,
    timeout: int = 10,
    cors: bool = True,
    check_takeover: bool = True,
    limit: int | None = None,
    extra_paths: list[str] | None = None,
    log: Callable[[str], None] = lambda _m: None,
    **enum_kwargs,
) -> ScanResult:
    subs = enumerate_subdomains(domain, resolve=True, log=log, **enum_kwargs)
    live = [r for name, r in sorted(subs.resolved.items()) if name in subs.found and r.alive]
    if limit:
        live = live[:limit]
    result = ScanResult(subs.domain, subs)
    log(f"[scan] auditing {len(live)} live hosts with {http_threads} threads ...")
    with ThreadPoolExecutor(max_workers=http_threads) as pool:
        futures = [pool.submit(audit_host, r, timeout=timeout, cors=cors,
                               check_takeover=check_takeover, extra_paths=extra_paths)
                   for r in live]
        for i, fut in enumerate(as_completed(futures), 1):
            h = fut.result()
            result.hosts.append(h)
            grade = h.report.grade if h.report else "-"
            log(f"[scan] ({i}/{len(live)}) {h.name}: {grade}" + (" TAKEOVER?" if h.takeover else ""))
    result.hosts.sort(key=sort_key)
    return result
