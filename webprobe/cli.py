"""
Command Line Interface and execution orchestrator for webprobe.
"""

import argparse
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Set

from webprobe.checks import ALL_CHECKS, GLOBAL_EARLY, GLOBAL_LATE, POINT_CHECKS, PROFILES
from webprobe.core.crawler import build_points, crawl
from webprobe.core.http import HttpClient, ensure_scheme
from webprobe.core.logger import (
    ActivityLog,
    C,
    format_findings_json,
    format_findings_text,
    log,
)
from webprobe.core.models import Ctx, Finding, Point
from webprobe.core.safety import (
    InstabilityMonitor,
    aborted,
    check_abort_file,
    in_testing_window,
)

VERSION = "3.0.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webprobe",
        description="webprobe - Authorized Web Application Vulnerability & Logic Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", nargs="?", default="", help="Target URL (e.g. https://example.com)")
    p.add_argument("--profile", default="quick", choices=list(PROFILES.keys()),
                   help="Scan profile to execute (default: quick)")
    p.add_argument("--checks", default="",
                   help="Comma-separated check names to run (overrides --profile)")
    p.add_argument("--list-checks", action="store_true",
                   help="List all registered checks by phase and exit")
    p.add_argument("--self-check", action="store_true",
                   help="Verify internal registries and consistency then exit 0")

    # Operational & Safety Controls
    g_safety = p.add_argument_group("Operational & Safety Controls")
    g_safety.add_argument("--rate-limit", type=float, default=5.0,
                          help="Maximum requests per second (default: 5.0)")
    g_safety.add_argument("--threads", type=int, default=4,
                          help="Worker threads for crawling and probing (default: 4)")
    g_safety.add_argument("--testing-hours", default="",
                          help="Allowed execution window in HH:MM-HH:MM (e.g. 10:00-20:00)")
    g_safety.add_argument("--abort-file", default="webprobe.abort",
                          help="Emergency abort file path (default: webprobe.abort)")
    g_safety.add_argument("--activity-log", default="",
                          help="File path to write detailed TSV audit log")
    g_safety.add_argument("--instability-threshold", type=float, default=0.20,
                          help="5xx error rate triggering backoff/halt (default: 0.20)")
    g_safety.add_argument("--instability-samples", type=int, default=30,
                          help="Minimum requests before instability monitor triggers (default: 30)")
    g_safety.add_argument("--insecure", action="store_true",
                          help="Disable SSL/TLS certificate verification")
    g_safety.add_argument("--verbose", action="store_true",
                          help="Enable verbose debugging output")

    # Recon & Crawl Controls
    g_crawl = p.add_argument_group("Crawling & Discovery")
    g_crawl.add_argument("--crawl-depth", type=int, default=2,
                         help="Maximum link crawl depth (default: 2)")
    g_crawl.add_argument("--max-pages", type=int, default=40,
                         help="Maximum pages to crawl (default: 40)")
    g_crawl.add_argument("--max-points", type=int, default=60,
                         help="Maximum parameter points to test (default: 60)")
    g_crawl.add_argument("--max-js", type=int, default=20,
                         help="Maximum JavaScript files to parse (default: 20)")
    g_crawl.add_argument("--discover-max", type=int, default=120,
                         help="Maximum paths to probe in directory discovery (default: 120)")
    g_crawl.add_argument("--discover-recursive", action="store_true",
                         help="Enable recursive directory discovery and mutations")
    g_crawl.add_argument("--param-discovery", action="store_true",
                         help="Enable hidden query parameter brute-force")
    g_crawl.add_argument("--param-max", type=int, default=25,
                         help="Maximum endpoints to test for hidden parameters (default: 25)")
    g_crawl.add_argument("--wayback", action="store_true",
                         help="Query Wayback Machine CDX API for historical endpoint seeds")

    # Authentication & Identity Controls
    g_auth = p.add_argument_group("Authentication & Identity")
    g_auth.add_argument("--cookie", default="",
                        help="Primary authenticated session cookie header string")
    g_auth.add_argument("--test-email", default="",
                        help="Synthetic test account email/username")
    g_auth.add_argument("--test-password", default="",
                        help="Synthetic test account password")
    g_auth.add_argument("--secondary-cookie", default="",
                        help="Secondary test user cookie (for cross-tenant IDOR checks)")
    g_auth.add_argument("--staff-cookie", default="",
                        help="Staff account cookie (for vertical privilege escalation checks)")
    g_auth.add_argument("--admin-cookie", default="",
                        help="Admin account cookie (for administrative endpoint testing)")
    g_auth.add_argument("--admin-login", action="store_true",
                        help="Enable default admin credential probes")
    g_auth.add_argument("--password-policy-test", action="store_true",
                        help="Enable weak password policy test probes")
    g_auth.add_argument("--rate-test", action="store_true",
                        help="Enable login rate-limiting / lockout probes")
    g_auth.add_argument("--rate-count", type=int, default=6,
                        help="Number of rate-limit probes to fire (default: 6)")

    # Extended Injection & Business Logic
    g_logic = p.add_argument_group("Injection & Business Logic")
    g_logic.add_argument("--time-based", action="store_true",
                         help="Enable time-based SQLi / stacked queries probes")
    g_logic.add_argument("--second-order", action="store_true",
                         help="Enable second-order injection probes via storage forms")
    g_logic.add_argument("--stored-xss", action="store_true",
                         help="Enable stored XSS probe against input forms")
    g_logic.add_argument("--test-coupon", default="",
                         help="Valid test coupon code for business logic checks")
    g_logic.add_argument("--expired-coupon", default="",
                         help="Known expired test coupon code")
    g_logic.add_argument("--ineligible-coupon", default="",
                         help="Ineligible test coupon code")
    g_logic.add_argument("--state-url", default="",
                         help="URL prefix for state-transition probes")
    g_logic.add_argument("--state-actions", default="",
                         help="Comma-separated state actions (e.g. cancel,refund,complete)")
    g_logic.add_argument("--refund-url", default="",
                         help="Refund endpoint URL for unauthorized refund checks")
    g_logic.add_argument("--webhook-url", default="",
                         help="Explicit payment webhook endpoint URL")
    g_logic.add_argument("--idempotency-test", action="store_true",
                         help="Enable booking/order creation replay test")

    # Output Options
    g_out = p.add_argument_group("Output Options")
    g_out.add_argument("-o", "--output", default="",
                       help="Save report to file")
    g_out.add_argument("--json", action="store_true",
                       help="Output report in JSON format")

    return p


def self_check() -> int:
    """Validate internal registry consistency and return 0 if clean."""
    print(f"[*] webprobe v{VERSION} self-check...")
    errors: List[str] = []

    # Check that all registered checks are callable
    for name, (phase, fn) in GLOBAL_EARLY.items():
        if not callable(fn):
            errors.append(f"GLOBAL_EARLY check '{name}' is not callable")
    for name, (phase, fn) in GLOBAL_LATE.items():
        if not callable(fn):
            errors.append(f"GLOBAL_LATE check '{name}' is not callable")
    for name, (phase, fn) in POINT_CHECKS.items():
        if not callable(fn):
            errors.append(f"POINT_CHECKS check '{name}' is not callable")

    # Check profiles
    for prof, checks in PROFILES.items():
        for c in checks:
            if c not in ALL_CHECKS:
                errors.append(f"Profile '{prof}' references unknown check '{c}'")

    if errors:
        print(C.red(f"[!] Self-check FAILED with {len(errors)} error(s):"))
        for e in errors:
            print(f"  * {e}")
        return 1

    total_checks = len(ALL_CHECKS)
    early_cnt = len(GLOBAL_EARLY)
    late_cnt = len(GLOBAL_LATE)
    point_cnt = len(POINT_CHECKS)
    prof_cnt = len(PROFILES)

    print(C.green(
        f"[+] Self-check PASSED: {total_checks} total checks registered "
        f"({early_cnt} early, {late_cnt} late, {point_cnt} points across {prof_cnt} profiles)."
    ))
    return 0


def list_checks() -> None:
    print(f"\nwebprobe v{VERSION} Registered Check Catalog ({len(ALL_CHECKS)} checks):\n")
    print(f"{'Check Name':<24} {'Phase':<8} {'Scope':<12}")
    print("-" * 50)
    for name in ALL_CHECKS:
        if name in GLOBAL_EARLY:
            phase, _ = GLOBAL_EARLY[name]
            scope = "Global (Early)"
        elif name in GLOBAL_LATE:
            phase, _ = GLOBAL_LATE[name]
            scope = "Global (Late)"
        elif name in POINT_CHECKS:
            phase, _ = POINT_CHECKS[name]
            scope = "Point"
        else:
            phase, scope = 0, "Unknown"
        print(f"{name:<24} P{phase:<7} {scope:<12}")
    print("\nProfiles available:")
    for prof, chks in PROFILES.items():
        print(f"  * {prof:<12} ({len(chks)} checks): {', '.join(chks[:6])}...")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_check:
        return self_check()

    if args.list_checks:
        list_checks()
        return 0

    if not args.url:
        parser.print_help()
        print(C.red("\nError: target URL is required (or run --self-check / --list-checks)."))
        return 1

    base_url = ensure_scheme(args.url.strip())
    parsed_root = urllib.parse.urlsplit(base_url)
    root_url = f"{parsed_root.scheme}://{parsed_root.netloc}"

    # Verify testing window
    if args.testing_hours and not in_testing_window(args.testing_hours):
        print(C.red(f"[!] Current time is outside authorized testing window ({args.testing_hours}). Halting."))
        return 2

    # Check emergency abort
    if check_abort_file(args.abort_file):
        print(C.red(f"[!] Emergency abort file '{args.abort_file}' detected. Aborting."))
        return 3

    # Resolve checks to run
    if args.checks:
        requested = [c.strip() for c in args.checks.split(",") if c.strip()]
        checks = [c for c in requested if c in ALL_CHECKS]
    else:
        checks = PROFILES.get(args.profile, PROFILES["quick"])

    print(C.bold(f"[*] webprobe v{VERSION} initializing against {base_url}"))
    print(C.dim(f"[*] Profile: {args.profile} ({len(checks)} checks selected)"))
    print(C.dim(f"[*] Rate limit: {args.rate_limit} rps, Threads: {args.threads}"))

    # Operational monitors
    activity = ActivityLog(args.activity_log, version=VERSION) if args.activity_log else None
    instability = InstabilityMonitor(threshold=args.instability_threshold, min_samples=args.instability_samples)

    http = HttpClient(
        cookie=args.cookie,
        rps=args.rate_limit,
        insecure=args.insecure,
        verbose=args.verbose,
        abort_fn=lambda: check_abort_file(args.abort_file),
        instability=instability,
        activity=activity,
    )

    ctx = Ctx(
        http=http,
        args=args,
        base_url=base_url,
        root=root_url,
        activity=activity,
        instability=instability,
    )

    findings: List[Finding] = []
    t_start = time.monotonic()

    # 1. Run GLOBAL_EARLY checks (e.g. headers, robots, security.txt, session, cve)
    for name in list(GLOBAL_EARLY.keys()):
        if name not in checks:
            continue
        if aborted(ctx):
            print(C.red("[!] Abort condition met. Halting scan."))
            break
        try:
            _, fn = GLOBAL_EARLY[name]
            res = fn(ctx)
            if res:
                findings.extend(res)
        except SystemExit:
            print(C.red("[!] Abort triggered by HTTP client."))
            break
        except Exception as e:
            if args.verbose:
                log(f"[!] Error in check {name}: {e}", err=True)

    # 2. Crawl if any remaining check requires pages/discovered endpoints
    needs_crawl = any(c in GLOBAL_LATE for c in checks) or any(c in POINT_CHECKS for c in checks)
    pages: List[Dict[str, Any]] = []
    discovered: List[str] = []

    if needs_crawl and not aborted(ctx):
        print(C.dim(f"[*] Crawling {base_url} (depth={args.crawl_depth}, max_pages={args.max_pages})..."))
        try:
            pages, discovered = crawl(
                http,
                base_url,
                extra_seeds=ctx.extra_seeds,
                max_depth=args.crawl_depth,
                max_pages=args.max_pages,
            )
            ctx.pages = pages
            ctx.discovered = discovered
            print(C.dim(
                f"[*] Crawled {len(pages)} pages, discovered {len(discovered)} URLs "
                f"({len(ctx.extra_seeds)} seeds from robots/sitemap/wayback)."
            ))
        except SystemExit:
            print(C.red("[!] Abort triggered during crawl."))

    # 3. Run GLOBAL_LATE checks in insertion order
    for name in list(GLOBAL_LATE.keys()):
        if name not in checks:
            continue
        if aborted(ctx):
            print(C.red("[!] Abort condition met. Halting scan."))
            break
        try:
            _, fn = GLOBAL_LATE[name]
            res = fn(ctx)
            if res:
                findings.extend(res)
        except SystemExit:
            print(C.red("[!] Abort triggered by HTTP client."))
            break
        except Exception as e:
            if args.verbose:
                log(f"[!] Error in check {name}: {e}", err=True)

    # 4. Run POINT_CHECKS against parameter points
    active_point_checks = [c for c in checks if c in POINT_CHECKS]
    if active_point_checks and not aborted(ctx):
        all_disc = list(dict.fromkeys(ctx.discovered + ctx.extra_discovered))
        points = build_points(ctx.pages, all_disc, max_points=args.max_points)
        print(C.dim(f"[*] Built {len(points)} injection points. Executing point checks..."))

        def run_point(pt: Point) -> List[Finding]:
            pt_findings: List[Finding] = []
            for cname in active_point_checks:
                if aborted(ctx):
                    break
                try:
                    _, pfn = POINT_CHECKS[cname]
                    pt_res = pfn(ctx, pt)
                    if pt_res:
                        pt_findings.extend(pt_res)
                except Exception as e:
                    if args.verbose:
                        log(f"[!] Error in point check {cname}: {e}", err=True)
            return pt_findings

        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = [ex.submit(run_point, pt) for pt in points]
            for f in as_completed(futures):
                try:
                    pt_res = f.result()
                    if pt_res:
                        findings.extend(pt_res)
                except Exception:
                    pass

    duration = time.monotonic() - t_start

    # Output formatting
    if args.json:
        report = format_findings_json(
            findings,
            {
                "target": base_url,
                "version": VERSION,
                "profile": args.profile,
                "duration_seconds": round(duration, 2),
            },
        )
    else:
        report = format_findings_text(findings, duration)

    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(C.green(f"[+] Report written to {args.output}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())

