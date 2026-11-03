"""Command-line interface: ``reconkit subdomains|headers``."""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

from . import __version__
from .headers import analyze
from .subdomains import PASSIVE_SOURCES, enumerate_subdomains

COLORS = {"high": "31", "medium": "33", "low": "36", "info": "37", "ok": "32", "dim": "90"}


def _use_color(stream) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, color: str, enabled: bool) -> str:
    return f"\033[{COLORS[color]}m{text}\033[0m" if enabled else text


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #

def cmd_subdomains(args) -> int:
    sources = args.sources.split(",") if args.sources else None
    if sources:
        bad = [s for s in sources if s not in PASSIVE_SOURCES]
        if bad:
            log(f"unknown source(s): {', '.join(bad)}. choices: {', '.join(PASSIVE_SOURCES)}")
            return 2
    try:
        result = enumerate_subdomains(
            args.domain,
            passive=not args.no_passive,
            sources=sources,
            bruteforce=args.brute,
            wordlist=args.wordlist,
            resolve=not args.no_resolve,
            threads=args.threads,
            nameservers=args.nameserver or None,
            log=log if not args.quiet else (lambda _m: None),
        )
    except ValueError as exc:
        log(str(exc))
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    color = _use_color(sys.stdout)
    rows = result.to_dict()["subdomains"]
    if args.alive_only:
        rows = [r for r in rows if r["addresses"] or r["cnames"]]
    for r in rows:
        resolved = r["addresses"] is not None
        alive = bool(r["addresses"] or r["cnames"])
        detail = ""
        if r["cnames"]:
            detail += " -> " + ", ".join(r["cnames"])
        if r["addresses"]:
            detail += "  [" + ", ".join(r["addresses"]) + "]"
        if resolved and not alive:
            detail += "  (no DNS record)"
        name = c(r["name"], "ok" if alive else "dim", color)
        src = c(f"({', '.join(r['sources'])})", "dim", color)
        print(f"{name}{detail}  {src}")
    alive_n = sum(1 for r in result.to_dict()["subdomains"] if r["addresses"] or r["cnames"])
    log(f"\n{len(result.found)} names found, {alive_n} resolve")
    return 0


def cmd_headers(args) -> int:
    try:
        report = analyze(args.url, timeout=args.timeout, cors=not args.no_cors)
    except requests.RequestException as exc:
        log(f"request failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    color = _use_color(sys.stdout)
    print(f"URL:    {report.final_url}  (HTTP {report.status})")
    grade_color = "ok" if report.grade in "AB" else "medium" if report.grade == "C" else "high"
    print(f"Grade:  {c(report.grade, grade_color, color)}  (score {report.score}/100)\n")
    if report.status >= 400:
        print(c(f"warning: HTTP {report.status} - this may be an error page from a proxy, WAF or "
                "load balancer, whose headers can differ from the real site's.\n", "medium", color))
    if not report.findings:
        print(c("No issues found.", "ok", color))
    for f in report.findings:
        if f.severity == "info" and not args.verbose:
            continue
        tag = c(f"[{f.severity.upper():6}]", f.severity, color)
        print(f"{tag} {f.title}")
        print(f"         why: {f.why}")
        if f.fix:
            print(f"         fix: {f.fix}")
        if f.value and args.verbose:
            print(c(f"         got: {f.value}", "dim", color))
        print()
    hidden = sum(1 for f in report.findings if f.severity == "info")
    if hidden and not args.verbose:
        log(f"({hidden} informational notes hidden; use -v to show)")
    return 0


# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  reconkit subdomains example.com --brute --alive-only\n"
               "  reconkit headers https://example.com -v\n\n"
               "run 'reconkit <command> -h' for a command's options",
        description="Recon tools for learning and authorized testing. "
                    "Only scan targets you own or have permission to test.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    s = sub.add_parser(
        "subdomains", help="discover subdomains of a domain",
        description="Discover subdomains from certificate transparency logs and passive DNS, "
                    "optionally brute-forcing names from a wordlist.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  reconkit subdomains example.com\n"
               "  reconkit subdomains example.com --brute -w words.txt -t 100\n"
               "  reconkit subdomains example.com --no-passive --brute -n 1.1.1.1\n"
               "  reconkit subdomains example.com --alive-only --json > subs.json",
    )
    s.add_argument("domain", help="domain to enumerate, e.g. example.com")
    s.add_argument("--brute", action="store_true", help="also guess names from a wordlist via DNS")
    s.add_argument("-w", "--wordlist", help="wordlist for --brute (default: built-in list)")
    s.add_argument("--sources", help=f"comma-separated passive sources ({','.join(PASSIVE_SOURCES)})")
    s.add_argument("--no-passive", action="store_true", help="skip third-party lookups")
    s.add_argument("--no-resolve", action="store_true", help="don't resolve passive results")
    s.add_argument("--alive-only", action="store_true", help="only print names that resolve")
    s.add_argument("-t", "--threads", type=int, default=50,
                   help="parallel DNS lookups (default: %(default)s)")
    s.add_argument("-n", "--nameserver", action="append", help="DNS server to use (repeatable)")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    s.add_argument("--json", action="store_true", help="print results as JSON")
    s.set_defaults(func=cmd_subdomains)

    h = sub.add_parser(
        "headers", help="audit a URL's security headers",
        description="Fetch a URL and grade its security headers (HSTS, CSP, X-Frame-Options, "
                    "cookies, CORS, ...), explaining why each issue matters and how to fix it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  reconkit headers https://example.com\n"
               "  reconkit headers example.com -v          # https:// is assumed\n"
               "  reconkit headers example.com --json --no-cors",
    )
    h.add_argument("url", help="URL or bare host to fetch")
    h.add_argument("--no-cors", action="store_true", help="skip the CORS origin-reflection probe")
    h.add_argument("--timeout", type=int, default=15,
                   help="request timeout in seconds (default: %(default)s)")
    h.add_argument("-v", "--verbose", action="store_true", help="show info notes and raw values")
    h.add_argument("--json", action="store_true", help="print the report as JSON")
    h.set_defaults(func=cmd_headers)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130
