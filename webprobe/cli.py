"""
Command Line Interface and execution orchestrator for webprobe.
"""

import argparse
import json
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
    p.add_argument("--config", default="", help="Path to JSON configuration file (e.g. config/agraskbagheltourandtravels.json)")
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
    g_safety.add_argument("--tls-impersonate", default="",
                          help="Browser TLS fingerprint profile (chrome124, safari17, edge124, firefox120)")
    g_safety.add_argument("--oast", choices=["", "webhooksite", "interactsh"], default="",
                          help="Out-of-band collaborator provider (webhooksite)")
    g_safety.add_argument("--webhook-token", default="",
                          help="Webhook.site token / uuid for OAST testing")

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
    g_crawl.add_argument("--vhost-test", action="store_true",
                         help="Fuzz Host header against common subdomain prefixes")
    g_crawl.add_argument("--headless", action="store_true",
                         help="Use headless Chrome via CDP if available on port 9222")
    g_crawl.add_argument("--cdp-port", type=int, default=9222,
                         help="Chrome remote debugging port (default: 9222)")

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
    g_auth.add_argument("--oauth-test", action="store_true",
                        help="Audit OAuth/OIDC authorization flow security")

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
    g_logic.add_argument("--state-precondition", default="",
                         help="URL to call before state test; if step fails after "
                              "this is applied, no finding is raised")
    g_logic.add_argument("--state-actions", default="",
                         help="Comma-separated state actions (e.g. cancel,refund,complete)")
    g_logic.add_argument("--refund-url", default="",
                         help="Refund endpoint URL for unauthorized refund checks")
    g_logic.add_argument("--webhook-url", default="",
                         help="Explicit payment webhook endpoint URL")
    g_logic.add_argument("--idempotency-test", action="store_true",
                         help="Enable booking/order creation replay test")
    g_logic.add_argument("--otp-test", action="store_true",
                         help="Enable OTP brute-force probe (bounded to --rate-count)")
    g_logic.add_argument("--race-url", default="",
                         help="URL for race condition test (POST endpoint)")
    g_logic.add_argument("--race-data", default="",
                         help="POST body for race test (JSON string)")
    g_logic.add_argument("--race-count", type=int, default=20,
                         help="Number of concurrent requests to fire (default: 20)")
    g_logic.add_argument("--race-expect", type=int, default=None,
                         help="Expected number of successes; excess = race condition")
    g_logic.add_argument("--exploit", action="store_true",
                         help="Enable exploit chains (React2Shell, middleware "
                              "bypass, RLS, webhook, race)")
    g_logic.add_argument("--exploit-rce", action="store_true",
                         help="Opt-in: prove RCE via React2Shell (runs a "
                              "command on the server)")
    g_logic.add_argument("--rce-command", default="id",
                         help="Command to execute during --exploit-rce proof "
                              "(default: id)")
    g_logic.add_argument("--postex", default="",
                         help="Finding ID or category to execute post-exploitation proof for")
    g_logic.add_argument("--chain", action="store_true", default=True,
                         help="Chain related findings into compound exploits (default: on)")
    g_logic.add_argument("--no-chain", dest="chain", action="store_false")

    # Output Options
    g_out = p.add_argument_group("Output Options")
    g_out.add_argument("-o", "--output", default="",
                       help="Save report to file")
    g_out.add_argument("--json", action="store_true",
                       help="Output report in JSON format")
    g_out.add_argument("--md", default="",
                       help="Save report to Markdown file")
    g_out.add_argument("--sarif", action="store_true",
                       help="Emit SARIF 2.1.0 format (in addition to --output)")
    g_out.add_argument("--sarif-path", default="webprobe.sarif",
                       help="SARIF output path (default: webprobe.sarif)")
    g_out.add_argument("--redact", action="store_true", default=True,
                       help="Redact PII/secrets from evidence (default: on)")
    g_out.add_argument("--no-redact", dest="redact", action="store_false")
    g_out.add_argument("--ledger", default="",
                       help="Append tamper-evident HMAC ledger to this file")
    g_out.add_argument("--aimd", action="store_true",
                       help="Adaptive rate limiting (overrides --rate-limit)")

    return p


def self_check() -> int:
    """Validate internal registry consistency and return 0 if clean."""
    print(f"[*] webprobe v{VERSION} self-check...")
    errors: List[str] = []

    # Check that all registered checks are callable and have valid phases [1..6]
    for name, (phase, fn) in GLOBAL_EARLY.items():
        if not callable(fn):
            errors.append(f"GLOBAL_EARLY check '{name}' is not callable")
        if phase not in (1, 2, 3, 4, 5, 6):
            errors.append(f"GLOBAL_EARLY check '{name}' has invalid phase {phase}")
    for name, (phase, fn) in GLOBAL_LATE.items():
        if not callable(fn):
            errors.append(f"GLOBAL_LATE check '{name}' is not callable")
        if phase not in (1, 2, 3, 4, 5, 6):
            errors.append(f"GLOBAL_LATE check '{name}' has invalid phase {phase}")
    for name, (phase, fn) in POINT_CHECKS.items():
        if not callable(fn):
            errors.append(f"POINT_CHECKS check '{name}' is not callable")
        if phase not in (1, 2, 3, 4, 5, 6):
            errors.append(f"POINT_CHECKS check '{name}' has invalid phase {phase}")

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
            scope = "Parameter Point"
        else:
            phase, scope = 0, "Unknown"
        print(f"{name:<24} P{phase:<7} {scope:<12}")
    print("\nProfiles available:")
    for prof, checks in PROFILES.items():
        print(f"  * {prof:<12} ({len(checks)} checks)")
    print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_check:
        return self_check()

    if args.list_checks:
        list_checks()
        return 0

    # Load configuration file if specified
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                for k, v in cfg.items():
                    attr = k.replace("-", "_")
                    if hasattr(args, attr):
                        # Config file values do not overwrite explicit CLI arguments
                        cli_val = getattr(args, attr)
                        parser_default = parser.get_default(attr)
                        if cli_val == parser_default:
                            setattr(args, attr, v)
        except Exception as e:
            print(C.red(f"[!] Error loading config {args.config}: {e}"))
            return 1

    if not args.url:
        parser.print_help()
        return 1

    base_url = ensure_scheme(args.url.rstrip("/"))
    sp = urllib.parse.urlsplit(base_url)
    root_url = f"{sp.scheme}://{sp.netloc}"

    # Verify operational testing window
    if not in_testing_window(args.testing_hours):
        print(C.yellow(f"[!] Current time outside authorized testing hours window: {args.testing_hours}"))
        return 2

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
    ledger = None
    if getattr(args, "ledger", ""):
        from webprobe.core.ledger import Ledger
        ledger = Ledger(args.ledger)

    activity = None
    if args.activity_log or ledger:
        activity = ActivityLog(args.activity_log or "", version=VERSION, ledger=ledger)

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

    if getattr(args, "aimd", False):
        from webprobe.core.aimd import AIMD
        aimd = AIMD(initial_rps=args.rate_limit or 5.0)
        http.set_aimd(aimd)
        print(C.dim(f"[*] AIMD rate limiter active (initial {aimd.rps:.1f} rps)"))

    if getattr(args, "tls_impersonate", ""):
        from webprobe.core.tlsfp import TLSClient
        http.set_tls_client(TLSClient(impersonate=args.tls_impersonate, insecure=args.insecure))

    ctx = Ctx(
        http=http,
        args=args,
        base_url=base_url,
        root=root_url,
        activity=activity,
        instability=instability,
    )

    if getattr(args, "oast", "") == "webhooksite":
        from webprobe.core.oast import OASTBridge
        bridge = OASTBridge(token=getattr(args, "webhook_token", ""))
        http.set_oast(bridge)
        ctx.collab = bridge

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
                ctx=ctx,
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

    # Redaction
    if getattr(args, "redact", True):
        from webprobe.core.redact import redact_finding
        for f in findings:
            redact_finding(f)

    # Exploit chains
    if getattr(args, "chain", True):
        from webprobe.exploits.chainer import check_exploit_chains
        findings.extend(check_exploit_chains(ctx, findings))

    # Post-exploitation proof execution if requested
    if getattr(args, "postex", ""):
        from webprobe.exploits.postex import generate_non_destructive_proof
        for f in list(findings):
            if f.category == args.postex or args.postex in f.title.lower():
                def _invoke(cmd: str) -> Optional[str]:
                    r = http.fetch(f.url, "POST", data={"cmd": cmd})
                    return r.text if r else None
                proof = generate_non_destructive_proof(ctx, f, invoke=_invoke)
                if proof:
                    findings.append(proof)

    # SARIF output
    if getattr(args, "sarif", False):
        from webprobe.core.sarif import build_sarif
        sarif_json = build_sarif(findings, target=base_url)
        with open(args.sarif_path, "w", encoding="utf-8") as fh:
            fh.write(sarif_json)
        print(C.green(f"[+] SARIF written to {args.sarif_path}"))

    # HMAC ledger
    if getattr(args, "ledger", ""):
        if ledger is None:
            from webprobe.core.ledger import Ledger
            ledger = Ledger(args.ledger)
        for f in findings:
            ledger.append(f.category, f.severity, f.title,
                          f.evidence[:400], url=f.url)
        print(C.green(f"[+] Ledger written to {args.ledger}"))

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

    if getattr(args, "md", ""):
        md_lines = [
            f"# webprobe Security Report - {base_url}\n",
            f"- **Profile:** {args.profile}\n",
            f"- **Duration:** {duration:.2f}s\n",
            f"- **Total Findings:** {len(findings)}\n\n",
        ]
        for f in findings:
            md_lines.append(
                f"## [{f.severity.upper()}] {f.title}\n"
                f"- **Category:** {f.category}\n"
                f"- **URL:** {f.url}\n"
                f"- **Evidence:** {f.evidence}\n"
                f"- **Remediation:** {f.remediation}\n\n"
            )
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write("".join(md_lines))
        print(C.green(f"[+] Markdown report written to {args.md}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
