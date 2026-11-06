"""Command-line interface: ``reconkit subdomains|headers``."""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

from . import __version__
from .headers import analyze, analyze_paths
from .http import make_session
from .scan import scan
from .subdomains import PASSIVE_SOURCES, enumerate_subdomains

COLORS = {"high": "31", "medium": "33", "low": "36", "info": "37", "ok": "32", "dim": "90"}

BANNER = """
    ____  ________________  _   __ __ __________
   / __ \\/ ____/ ____/ __ \\/ | / / //_/  _/_  __/
  / /_/ / __/ / /   / / / /  |/ / ,<  / /  / /
 / _, _/ /___/ /___/ /_/ / /|  / /| |_/ / / /
/_/ |_/_____/\\____/\\____/_/ |_/_/ |_/___/ /_/
         reconnaissance toolkit v{ver}
"""


def print_banner() -> None:
    if not sys.stderr.isatty() or os.environ.get("NO_COLOR"):
        return
    text = BANNER.replace("{ver}", __version__)
    print(f"\033[36m{text}\033[0m", file=sys.stderr)


def _use_color(stream) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, color: str, enabled: bool) -> str:
    return f"\033[{COLORS[color]}m{text}\033[0m" if enabled else text


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def save_output(args, data: dict) -> None:
    """Write JSON to -o FILE if given (in addition to normal output)."""
    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        log(f"saved JSON report to {args.output}")


def check_sources(args) -> list[str] | None:
    sources = args.sources.split(",") if args.sources else None
    if sources:
        bad = [s for s in sources if s not in PASSIVE_SOURCES]
        if bad:
            raise ValueError(f"unknown source(s): {', '.join(bad)}. choices: {', '.join(PASSIVE_SOURCES)}")
    return sources


def enum_kwargs(args) -> dict:
    return dict(
        passive=not args.no_passive,
        sources=check_sources(args),
        bruteforce=args.brute,
        wordlist=args.wordlist,
        threads=args.threads,
        nameservers=args.nameserver or None,
    )


# --------------------------------------------------------------------------- #

def _session_from_args(args) -> requests.Session | None:
    ua = getattr(args, "user_agent", None)
    return make_session(ua) if ua else None


def cmd_subdomains(args) -> int:
    try:
        result = enumerate_subdomains(
            args.domain,
            resolve=not args.no_resolve,
            log=log if not args.quiet else (lambda _m: None),
            session=_session_from_args(args),
            **enum_kwargs(args),
        )
    except ValueError as exc:
        log(str(exc))
        return 2

    save_output(args, result.to_dict())
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
        if r.get("dangling"):
            detail += "  " + c("(CNAME target does not resolve: possible takeover)", "high", color)
        elif r.get("dns_error"):
            detail += "  " + c(f"(DNS error: {r['dns_error']})", "medium", color)
        elif resolved and not alive:
            detail += "  (no DNS record)"
        name = c(r["name"], "ok" if alive else "dim", color)
        src = c(f"({', '.join(r['sources'])})", "dim", color)
        print(f"{name}{detail}  {src}")
    alive_n = sum(1 for r in result.to_dict()["subdomains"] if r["addresses"] or r["cnames"])
    log(f"\n{len(result.found)} names found, {alive_n} resolve")
    return 0


def _print_report(report, color: bool, verbose: bool) -> None:
    print(f"URL:    {report.final_url}  (HTTP {report.status})")
    if report.blocked_by:
        print(c(f"\nBLOCKED by {report.blocked_by} bot protection. The response is a challenge page, "
                "not the real site. Header grades would be meaningless.\n"
                "Try from an allowed IP, or skip this host.", "high", color))
        return
    grade_color = "ok" if report.grade in "AB" else "medium" if report.grade == "C" else "high"
    print(f"Grade:  {c(report.grade, grade_color, color)}  (score {report.score}/100)\n")
    if report.meta_csp:
        print(c("note: CSP was set via <meta> tag, not an HTTP header.\n", "medium", color))
    if report.status >= 400:
        print(c(f"warning: HTTP {report.status} - this may be an error page from a proxy, WAF or "
                "load balancer, whose headers can differ from the real site's.\n", "medium", color))
    if not report.findings:
        print(c("No issues found.", "ok", color))
    for f in report.findings:
        if f.severity == "info" and not verbose:
            continue
        tag = c(f"[{f.severity.upper():6}]", f.severity, color)
        print(f"{tag} {f.title}")
        print(f"         why: {f.why}")
        if f.fix:
            print(f"         fix: {f.fix}")
        if f.value and verbose:
            print(c(f"         got: {f.value}", "dim", color))
        print()
    hidden = sum(1 for f in report.findings if f.severity == "info")
    if hidden and not verbose:
        log(f"({hidden} informational notes hidden; use -v to show)")


def cmd_headers(args) -> int:
    paths = args.paths.split(",") if getattr(args, "paths", None) else None
    session = _session_from_args(args)
    try:
        if paths:
            reports = analyze_paths(args.url, paths, timeout=args.timeout,
                                    cors=not args.no_cors, redirect=not args.no_redirect,
                                    session=session)
        else:
            reports = [analyze(args.url, timeout=args.timeout, cors=not args.no_cors,
                               redirect=not args.no_redirect, session=session)]
    except requests.RequestException as exc:
        log(f"request failed: {exc}")
        return 1

    if not reports:
        log("no paths returned a response")
        return 1

    all_data = [r.to_dict() for r in reports]
    save_output(args, all_data[0] if len(all_data) == 1 else {"paths": all_data})
    if args.json:
        out = all_data[0] if len(all_data) == 1 else {"paths": all_data}
        print(json.dumps(out, indent=2))
        return 0

    color = _use_color(sys.stdout)
    for i, report in enumerate(reports):
        if i > 0:
            print(c("\n" + "=" * 60 + "\n", "dim", color))
        _print_report(report, color, args.verbose)
    return 0


def cmd_scan(args) -> int:
    extra_paths = args.paths.split(",") if getattr(args, "paths", None) else None
    try:
        result = scan(
            args.domain,
            http_threads=args.http_threads,
            timeout=args.timeout,
            cors=not args.no_cors,
            check_takeover=not args.no_takeover,
            limit=args.limit,
            extra_paths=extra_paths,
            log=log if not args.quiet else (lambda _m: None),
            **enum_kwargs(args),
        )
    except ValueError as exc:
        log(str(exc))
        return 2

    save_output(args, result.to_dict())
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    color = _use_color(sys.stdout)
    hosts = result.hosts
    if not hosts:
        print("No live hosts found.")
        return 0

    width = max(len(h.name) for h in hosts)
    print(f"\n{'HOST':<{width}}  HTTP  GRADE  HIGH MED LOW  TOP ISSUE")
    for h in hosts:
        if h.report and h.report.blocked_by:
            status = str(h.report.status)
            blk = c("BLOCKED", "high", color)
            cols = f"{status:<4}  {blk}  {'':>4} {'':>3} {'':>3}  bot protection ({h.report.blocked_by})"
        elif h.report:
            k = h.counts()
            grade = h.report.grade
            gcol = "ok" if grade in "AB" else "medium" if grade == "C" else "high"
            top = next((f.title for f in h.report.findings if f.severity in ("high", "medium")), "")
            status = str(h.report.status)
            cols = f"{status:<4}  {c(grade, gcol, color)}{' ' * 4}  {k['high']:>4} {k['medium']:>3} {k['low']:>3}  {top}"
        else:
            cols = c(f"{'-':<4}  {'-':<5}  {'':>4} {'':>3} {'':>3}  {h.error or ''}", "dim", color)
        print(f"{h.name:<{width}}  {cols}")

    if result.takeovers:
        print(c(f"\nPossible subdomain takeovers ({len(result.takeovers)}) - verify manually:", "high", color))
        for t in result.takeovers:
            svc = t.service or "unknown service"
            print(f"  {c(t.confidence.upper(), 'high', color)} {t.name} -> {' -> '.join(t.cnames)}  [{svc}]")
            for e in t.evidence:
                print(f"         {e}")
    if any(h.path_reports for h in hosts):
        print(c("\nPer-path findings:", "medium", color))
        for h in hosts:
            for pr in h.path_reports:
                if pr.blocked_by:
                    print(f"  {h.name} {pr.final_url}: {c('BLOCKED', 'high', color)} ({pr.blocked_by})")
                elif pr.findings:
                    worst = next((f for f in pr.findings if f.severity in ("high", "medium")), pr.findings[0])
                    gcol = "ok" if pr.grade in "AB" else "medium" if pr.grade == "C" else "high"
                    print(f"  {h.name} {pr.final_url}: {c(pr.grade, gcol, color)} - {worst.title}")

    graded = [h for h in hosts if h.report]
    weak = sum(1 for h in graded if h.report.grade in "DF")
    log(f"\n{len(hosts)} live hosts, {len(graded)} answered HTTP(S), {weak} graded D or F, "
        f"{len(result.takeovers)} possible takeovers")
    return 0


# --------------------------------------------------------------------------- #

def add_enum_options(s: argparse.ArgumentParser) -> None:
    s.add_argument("--brute", action="store_true", help="also guess names from a wordlist via DNS")
    s.add_argument("-w", "--wordlist", help="wordlist for --brute (default: built-in list)")
    s.add_argument("--sources", help=f"comma-separated passive sources ({','.join(PASSIVE_SOURCES)})")
    s.add_argument("--no-passive", action="store_true", help="skip third-party lookups")
    s.add_argument("-t", "--threads", type=int, default=50,
                   help="parallel DNS lookups (default: %(default)s)")
    s.add_argument("-n", "--nameserver", action="append", help="DNS server to use (repeatable)")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress messages")


def add_output_options(s: argparse.ArgumentParser) -> None:
    s.add_argument("--json", action="store_true", help="print results as JSON")
    s.add_argument("-o", "--output", metavar="FILE", help="also save the full results as JSON to FILE")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  reconkit scan example.com --brute -o report.json\n"
               "  reconkit subdomains example.com --brute --alive-only\n"
               "  reconkit headers https://example.com -v\n\n"
               "run 'reconkit <command> -h' for a command's options",
        description="Recon tools for learning and authorized testing. "
                    "Only scan targets you own or have permission to test.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--user-agent", metavar="UA",
                   help="custom User-Agent header (default: reconkit/0.1)")
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
    add_enum_options(s)
    s.add_argument("--no-resolve", action="store_true", help="don't resolve passive results")
    s.add_argument("--alive-only", action="store_true", help="only print names that resolve")
    add_output_options(s)
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
    h.add_argument("--paths", help="comma-separated paths to check (e.g. /,/api,/admin)")
    h.add_argument("--no-cors", action="store_true", help="skip the CORS origin-reflection probe")
    h.add_argument("--no-redirect", action="store_true", help="skip the HTTP-to-HTTPS redirect check")
    h.add_argument("--timeout", type=int, default=15,
                   help="request timeout in seconds (default: %(default)s)")
    h.add_argument("-v", "--verbose", action="store_true", help="show info notes and raw values")
    add_output_options(h)
    h.set_defaults(func=cmd_headers)

    sc = sub.add_parser(
        "scan", help="find subdomains, then audit every live one",
        description="Enumerate subdomains, then for every host that resolves: grade its security "
                    "headers and check for dangling CNAMEs (possible subdomain takeover). "
                    "Results are sorted worst-first.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  reconkit scan example.com\n"
               "  reconkit scan example.com --brute -o report.json\n"
               "  reconkit scan example.com --no-passive --brute --http-threads 20",
    )
    sc.add_argument("domain", help="domain to scan, e.g. example.com")
    add_enum_options(sc)
    sc.add_argument("--http-threads", type=int, default=10,
                    help="hosts audited in parallel (default: %(default)s)")
    sc.add_argument("--timeout", type=int, default=10,
                    help="per-request timeout in seconds (default: %(default)s)")
    sc.add_argument("--limit", type=int, help="audit at most this many hosts")
    sc.add_argument("--paths", help="comma-separated paths to also check per host (e.g. /api,/admin)")
    sc.add_argument("--no-cors", action="store_true", help="skip the CORS probe on each host")
    sc.add_argument("--no-takeover", action="store_true", help="skip dangling-CNAME checks")
    add_output_options(sc)
    sc.set_defaults(func=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "json", False) and not getattr(args, "quiet", False):
        print_banner()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130
