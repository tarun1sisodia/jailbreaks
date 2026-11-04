# AGENT_FIX_PROTOCOL — webprobe phase 6 remediation

## Purpose

Bring the current webprobe codebase from "patches applied, not integrated,
known bugs unfixed" to "all modules wired, all tests passing, smoke-tested
against localhost, ready for staged rollout against the real target."

## Rules of engagement

1. **Never proceed past a failed gate.** Each phase ends with an explicit
   check. If it fails, STOP and report — do not "fix forward" by skipping.
2. **Commit after every phase.** Branch: `fix/phase6-integration`. One
   commit per phase. Commit message format: `phase-N: <summary>`.
3. **Test-first for bug fixes.** For each bug, write the failing test,
   confirm it fails with the documented symptom, then fix, then confirm
   it passes. Bug and test commit together.
4. **Never edit a file the phase doesn't name.** If a fix seems to require
   touching a file outside the current phase's scope, STOP and report.
5. **Do not rewrite a file unless the phase says "rewrite".** If the
   phase says "append" or "patch", the existing content must be preserved.
6. **If `pytest` fails at any point, that phase is not done.** Report the
   exact failure; do not suppress with `-k` filters.

## Reporting format — required after every phase

The agent must produce this at the end of each phase:

```
PHASE: <N>
STATUS: PASS | FAIL | BLOCKED
FILES TOUCHED: <list>
TESTS: <X passed, Y failed>
COMMIT: <hash> <message>
NOTES: <anything anomalous>
NEXT PHASE READINESS: <yes | no + reason>
```

A phase is only PASS if every acceptance criterion is met.

---

# Phase 0 — Baseline (establish ground truth)

**Do not change code in this phase. This phase records what's broken.**

## Steps

1. `git checkout -b fix/phase6-integration`
2. Run and capture output:
   ```bash
   python -m py_compile webprobe.py
   python -m py_compile $(find webprobe -name '*.py') 2>&1 | tee baseline_compile.log
   python webprobe.py --self-check 2>&1 | tee baseline_selfcheck.log
   python -m pytest -v 2>&1 | tee baseline_pytest.log
   ```
3. Write `baseline_report.md` summarizing:
   - Which files fail to compile, with tracebacks
   - What `--self-check` reports (counts, errors)
   - What `pytest` reports (passed / failed / errored)

## Acceptance criteria

- All three baseline logs exist
- `baseline_report.md` enumerates every failure

## STOP condition

If `webprobe.py` itself does not import (i.e., `--self-check` cannot run at all),
that's a separate structural problem. STOP and report the traceback before
attempting any other phase.

---

# Phase 1 — Bug fixes (10 known bugs)

Each bug gets: failing test → fix → passing test → commit.

## Bug 1 — `check_jwt_rs_hs_confusion`: `name` variable scope

**File:** `webprobe/checks/phase2_auth.py`
**Symptom:** `NameError: name 'name' is not defined` when the token comes from
page scraping rather than `ctx.tokens`.

**Step 1a — write failing test:**
Create `tests/test_jwt.py`:

```python
def test_jwt_rs_hs_token_from_page(mock_server, ctx_factory):
    """Regression: `name` must default when token comes from HTML, not ctx.tokens."""
    base_url, routes, log, _ = mock_server
    # RSA-encoded JWT in page HTML, no ctx.tokens populated
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln"
    routes["GET /"] = (200, f'<html><script>var t="{fake_jwt}"</script></html>',
                       {"Content-Type": "text/html"})
    ctx = ctx_factory({"exploit": True})
    ctx.pages = [{"url": base_url + "/", "html": routes["GET /"][1]}]
    from webprobe.checks.phase2_auth import check_jwt_rs_hs_confusion
    # Must not raise NameError
    result = check_jwt_rs_hs_confusion(ctx)
    assert isinstance(result, list)
```

**Step 1b — confirm it fails** with `NameError`.

**Step 1c — fix:** In `check_jwt_rs_hs_confusion`, initialize `cookie_name = "token"`
before the token-search block, and use `cookie_name` throughout (not `name`).

**Step 1d — confirm test passes.**

---

## Bug 2 — `check_jwt_jku`: same `name` scope bug

**File:** `webprobe/checks/phase2_auth.py`
**Fix:** Replace all references to `name` in the loop body with a variable
defined before the loop. Same pattern as Bug 1.

**Test:** same file, `test_jwt_jku_no_name_error`.

---

## Bug 3 — `check_session_revocation`: `r.links` does not exist

**File:** `webprobe/checks/phase2_auth.py`
**Symptom:** `AttributeError: 'Response' object has no attribute 'links'`.

**Step 3a — write failing test:** use `mock_server` with a login form + logout
link in HTML; confirm the function raises.

**Step 3b — fix:** replace the `r.links` block with `parse_page(r.text, r.url)[0]`
(links are the first element of the tuple from `parse_page`). Remove the
`hasattr` guard.

**Step 3c — confirm test passes.**

---

## Bug 4 — `check_cors_dynamic`: f-string attribute access

**File:** `webprobe/checks/phase6_infra.py`
**Symptom:** `SyntaxError` on Python < 3.12 due to
`f"https://{ctx.base_url.split('://')[-1].split('/')[0]}.evil.example"`.
The `.evil.example` after `]` parses as attribute access.

**Step 4a — write failing test:** `tests/test_cors.py::test_cors_dynamic_parses`
that imports the module — `SyntaxError` fails at import.

**Step 4b — fix:** extract the host to a variable first:

```python
host = ctx.base_url.split("://")[-1].split("/")[0]
test_origins = [
    "null",
    "https://evil.example",
    "https://attacker.evil.example",
    f"https://{host}.evil.example",
    f"https://evil{host}",
    "https://target.example.evil.example",
]
```

**Step 4c — confirm test passes.**

---

## Bug 5 — `check_rbac_matrix`: tautological body comparison

**File:** `webprobe/checks/phase4_authorization.py`
**Symptom:** `bodies[label][:500] == bodies[label][:500]` always True; the check
fires on any two 200s regardless of content.

**Step 5a — write failing test:**

```python
def test_rbac_matrix_different_content(mock_server, ctx_factory):
    """Two roles return 200 but DIFFERENT bodies — must NOT be flagged as IDOR."""
    base_url, routes, log, _ = mock_server
    routes["GET /api/me"] = lambda h: _respond_by_cookie(h, {
        "session=alice": (200, '{"user":"alice","email":"a@x.com"}'),
        "session=bob":   (200, '{"user":"bob","email":"b@x.com"}'),
    })
    ctx = ctx_factory({"cookie": "session=alice", "secondary_cookie": "session=bob"})
    ctx.discovered = [base_url + "/api/me"]
    from webprobe.checks.phase4_authorization import check_rbac_matrix
    findings = check_rbac_matrix(ctx)
    idor = [f for f in findings if "identical" in f.title.lower()]
    assert idor == [], "different bodies must not be flagged as IDOR"
```

(`_respond_by_cookie` is a helper to add to `tests/conftest.py`; it reads
`Cookie` header from the request and dispatches by value.)

**Step 5b — confirm test fails** (current code flags it as IDOR).

**Step 5c — fix:** change

```python
if (row.get("customer") == 200 and row.get("secondary") == 200
        and bodies.get("customer", "")[:500] == bodies.get("secondary", "")[:500]
        and len(bodies.get("customer", "")) > 200):
```

to also require the *same* user identity in the body (compare after stripping
any `user`, `id`, `email` field differences):

```python
def _bodies_match_as_same_user(a: str, b: str) -> bool:
    import json, re
    try:
        ja, jb = json.loads(a), json.loads(b)
    except Exception:
        return a[:500] == b[:500]
    if not (isinstance(ja, dict) and isinstance(jb, dict)):
        return a[:500] == b[:500]
    # Strip identity-bearing fields before comparison
    IDENT = re.compile(r"(?i)^(user|user_id|id|email|owner_id|account_id)$")
    sa = {k: v for k, v in ja.items() if not IDENT.match(k)}
    sb = {k: v for k, v in jb.items() if not IDENT.match(k)}
    return sa == sb
```

Use `_bodies_match_as_same_user` instead of `==`.

**Step 5d — confirm test passes.**

---

## Bug 6 — `check_graphql_resolver`: nested-field regex fails

**File:** `webprobe/checks/phase4_authorization.py`
**Symptom:** regex `"fields":\[([^\]]+)\]` stops at the first `]`, missing all
nested fields. Most modern schemas have nested types, so the check silently
does nothing.

**Fix:** parse the introspection JSON properly:

```python
data = json.loads(intro.text)
types = data.get("data", {}).get("__schema", {}).get("types", []) or []
for t in types:
    fields = t.get("fields") or []
    sensitive = [f["name"] for f in fields
                 if re.search(r"(?i)(email|phone|admin|role|secret|"
                              r"password|invoice|payment|address|ssn)", f["name"])]
    if not sensitive:
        continue
    # ... rest unchanged
```

**Test:** introspection response with nested types that must be parsed.

---

## Bug 7 — `check_fsm_workflow`: fires without state context

**File:** `webprobe/checks/phase5_business_logic.py`
**Symptom:** calls each step in isolation, with no way to prove the step
*should* be rejected. Fires on every step.

**Fix:** require `--state-precondition` argument (a URL that must be called
first, or a string proving the resource's current state). Only flag when:

1. Step succeeds with no precondition, AND
2. Step fails after the precondition is applied

Add to `cli.py` in `g_logic` group:

```python
g_logic.add_argument("--state-precondition", default="",
                     help="URL to call before state test; if step fails after "
                          "this is applied, no finding is raised")
```

**Test:** mock server that requires a `prep` call before `/book/confirm`
succeeds — confirm the check does not flag when precondition is honored.

---

## Bug 8 — `check_numeric_precision`: same FP class as SSTI

**File:** `webprobe/checks/phase5_business_logic.py`
**Symptom:** fires on `0.01` if the page already contains `0.01` legitimately.

**Fix:** use unique sentinel values that never appear naturally:

```python
probes = [
    ("neg_zero", "-0.00"),
    ("float_overflow", "1e308"),
    ("int_overflow", "9223372036854775808"),
    ("tiny", "0.00000001"),
    ("fraction_split", "0.00001731"),  # prime-like; never a natural price
    ("negative", "-99999.37"),         # prime-like
]
```

Require the *exact sentinel* to appear and the base response to *not* contain
it.

**Test:** page contains `0.01` in a price; probe `0.00001731` must not match.

---

## Bug 9 — `exploits/postex.py`: returns template, doesn't execute

**File:** `webprobe/exploits/postex.py`
**Symptom:** `generate_non_destructive_proof` returns a Finding but never
executes anything.

**Fix:** the function signature must accept the RCE invocation callback:

```python
def generate_non_destructive_proof(ctx, rce_finding,
                                    invoke: Callable[[str], Optional[str]]) -> Optional[Finding]:
    """invoke(cmd) -> response text containing cmd output, or None."""
    if not getattr(ctx.args, "exploit_rce", False):
        return None
    results = {}
    for cmd, rx, label in proof_payloads():
        out = invoke(cmd)
        if out and rx.search(out):
            results[label] = rx.search(out).group(0)
    if not results:
        return None
    # ... build the Finding from results
```

The caller (React2Shell module, or a new `--postex <finding_id>` flow) supplies
the invoke callback.

**Test:** mock invoke that returns known output; assert the Finding contains
all captured fields.

---

## Bug 10 — `checks/__init__.py`: duplicate `ALL_CHECKS` sort

**File:** `webprobe/checks/__init__.py`
**Symptom:** appending my block after the existing `ALL_CHECKS = sorted(...)`
line produces two sorts. Not fatal, but the second one runs before the new
registries are fully updated in some load orders.

**Fix:** move the appended `ALL_CHECKS = sorted(...)` line to the *bottom* of
the file (after all `GLOBAL_EARLY.update`, `GLOBAL_LATE.update`,
`POINT_CHECKS.update` calls). Delete the earlier one.

**Test:** run `python -c "from webprobe.checks import ALL_CHECKS; print(len(ALL_CHECKS))"`
and confirm the count is stable across two runs.

---

## Phase 1 acceptance criteria

- All 10 bugs have a corresponding test in `tests/`
- Every test was observed to fail before its fix and pass after
- `pytest -v` reports **0 failed, 0 errored**
- Commit message: `phase-1: fix 10 known bugs with failing-first tests`

## STOP condition

If any fix causes a different test to fail, do not "adjust the fix" to
compensate. Revert that fix and report the interaction.

---

# Phase 2 — Missing test coverage

Write tests for the checks that currently have none. These are the checks that
have no protective test, so a future change can regress them silently.

## Tests to add

1. `tests/test_recon.py` — `check_robots`, `check_security_txt`,
   `check_manifest_routes`, `check_graphql_js_schema`
2. `tests/test_auth.py` — `check_enumeration`, `check_jwt_rs_hs_confusion`,
   `check_jwt_jku` (callback-based), `check_oauth_audit`
3. `tests/test_injection.py` — `check_blind_time` (with `set_delay(3000)`),
   `check_xss_ast` (context classification), `check_unicode_desync`
4. `tests/test_authz.py` — `check_idor_resources`, `check_mass_assign_schema`,
   `check_rbac_matrix`, `check_graphql_resolver`
5. `tests/test_infra.py` — `check_cors_dynamic` (6 origin patterns),
   `check_cache_deception`, `check_cookie_flags`, `check_debug_flags`
6. `tests/test_exploits.py` — `check_nextjs_middleware_bypass`,
   `check_rsc_cache_poison`, `check_razorpay_webhook_bypass`

## Test discipline — one true positive, one true negative per check

Every check MUST have at least:
- one test that constructs a **vulnerable** mock and asserts `len(findings) > 0`
- one test that constructs a **safe** mock and asserts `findings == []`

The negative test is the more important one — that's what prevents future FPs.

## Phase 2 acceptance criteria

- Every check function in `webprobe/checks/` and `webprobe/exploits/` has
  at least 2 tests (positive + negative)
- `pytest -v` reports **0 failed**
- `pytest --collect-only | grep "test "` count ≥ 2 × (number of checks)
- Commit message: `phase-2: test coverage for all checks (pos + neg)`

---

# Phase 3 — Integration pass

**This phase rewrites 6 files.** Each rewrite has a strict scope. Preserve
every public function signature, every class interface, and every existing
behavior that isn't explicitly being added to.

## File 3.1 — `webprobe/core/models.py` (rewrite)

**Preserve:** all existing dataclasses and their fields.

**Add:**
- `Finding.__post_init__` populates `extra["cvss"]` and `extra["taxonomy"]`
  via `core.cvss.score_for_category` and `core.taxonomy.lookup`
- `Finding.to_dict()` includes `extra` recursively (already does, verify)
- New field `Finding.poc: Optional[Dict] = None` for replay blobs
- `Response.__post_init__` sets `self.received_at = time.time()`

**Acceptance:** every test in `tests/test_checks.py` still passes. New test
`tests/test_models.py::test_finding_has_cvss_attached` passes.

---

## File 3.2 — `webprobe/core/safety.py` (append)

**Preserve:** everything. No signature changes.

**Add:**
- Import `AIMD` and instantiate lazily inside `InstabilityMonitor` — expose
  as `monitor.aimd` attribute so `HttpClient` can look it up
- New `scrub(text)` helper that calls `core.redact.redact_text` — used by
  `ActivityLog.record`

**Acceptance:** `tests/test_http.py::test_http_client_rate_limit` still passes.

---

## File 3.3 — `webprobe/core/logger.py` (rewrite)

**Preserve:** `C` class, `log()` function, `format_findings_text`,
`format_findings_json`.

**Add to `ActivityLog.__init__`:**
- optional `ledger: Optional[Ledger] = None` parameter
- if provided, `record()` writes to both TSV and ledger

**Add:**
- `ActivityLog.replay(limit: int)` returns last N entries (for `--self-check`)
- `ActivityLog.verify()` delegates to `ledger.verify()` if present

**Acceptance:** `tests/test_logger.py` (new) verifies TSV + ledger co-write
and tampering detection.

---

## File 3.4 — `webprobe/core/crawler.py` (patch, not rewrite)

**Preserve:** `parse_page`, `crawl`, `build_points` — no signature changes.

**Patch `crawl()`:**
- after the regex-based crawl completes, if `getattr(args, "headless", False)`
  and `cdp.headless_available(port=args.cdp_port)`, call `cdp.auto_crawl(ctx)`
  and merge the extra pages into the result
- call `manifest.extract_all(ctx)` and extend `discovered` with the routes

**Patch `build_points()`:**
- for each form, call `formfiller.fill_form(form)` and use the synthesized
  values as `orig_value` instead of empty strings

**Acceptance:** existing tests pass. New test
`tests/test_crawler.py::test_crawl_headless_merges` uses a stubbed CDP to
verify page merge without launching Chrome.

---

## File 3.5 — `webprobe/core/http.py` (patch)

**Preserve:** `HttpClient.__init__`, `fetch`, `_fetch_inner`, `clone` — all
signatures unchanged.

**Patch `fetch()`:**
- if `self._aimd` is set (attribute added by `cli.py`), call `self._aimd.throttle()`
  before the existing `self._throttle()`
- after the response, call `self._aimd.observe(elapsed)` if present

**Patch `_fetch_inner()`:**
- if `getattr(self, "tls_client", None)` is set, delegate to
  `self.tls_client.fetch()` and convert the tuple to a `Response`
- otherwise use the existing http.client path

**Add:**
- `HttpClient.set_tls_client(tls_client)` setter
- `HttpClient.set_oast(bridge: OASTBridge)` and `self.oast` attribute so
  checks can call `ctx.http.oast.payload_url(marker)`

**Acceptance:** `tests/test_http.py` all pass. New test
`tests/test_http.py::test_tls_client_delegates` uses a stub TLSClient.

---

## File 3.6 — `webprobe/cli.py` (rewrite)

**Preserve:** all existing flags.

**Add argument groups** (as in the previous response) plus:

- `--state-precondition` (for Bug 7)
- `--postex` (for Bug 9's execute path)

**In `main()`:**
- construct `AIMD` if `args.aimd`, call `http.set_aimd(aimd)`
- construct `TLSClient` if `args.tls_impersonate`, call `http.set_tls_client(...)`
- construct `OASTBridge` if `args.oast == "webhooksite"`, call
  `http.set_oast(...)` and `ctx.collab = http.oast` (so existing checks
  that use `ctx.collab` work)
- construct `Ledger` if `args.ledger`, pass to `ActivityLog`
- after findings collected: redact (if `args.redact`), enrich with CVSS +
  taxonomy (already in `Finding.__post_init__` after Phase 3.1), chain
  exploits, write SARIF if `args.sarif`
- **remove** the monkey-patch approach from the previous response
  (`http.fetch = _fetch_with_aimd`) — use `set_aimd` instead

**Acceptance:** `python webprobe.py --help` lists every new flag. `python
webprobe.py --self-check` passes with the new counts.

---

## Phase 3 acceptance criteria

- `python -m py_compile $(find webprobe -name '*.py')` — all clean
- `python webprobe.py --self-check` — exit 0, prints ≥ 60 checks
- `python webprobe.py --list-checks | wc -l` — matches `--self-check` count
- `pytest -v` — 0 failed
- Commit message: `phase-3: integrate sidecar modules into core`

## STOP condition

If any of the 6 rewrites changes a public function signature, STOP. A signature
change means an external caller will break. Report the signature change and
await approval before proceeding.

---

# Phase 4 — End-to-end smoke test against localhost

Nothing in this phase touches the real target. Everything runs against
`http://127.0.0.1:8765`.

## Steps

1. Start a deliberately vulnerable local server:

   Create `tests/fixtures/vuln_server.py` with an `http.server` that has:
   - `/search?q=` → reflects to HTML (XSS)
   - `/login` → POST with SQLi error on bad quote
   - `/api/me?id=1` → returns different user data by ID (IDOR)
   - `/admin` → returns 200 without auth (missing authz)
   - all headers intentionally weak (no CSP, no HSTS)

   ```bash
   python tests/fixtures/vuln_server.py --port 8765 &
   ```

2. Run each profile against it:

   ```bash
   for profile in quick recon auth injection authz business config owasp api; do
     echo "=== $profile ==="
     python webprobe.py http://127.0.0.1:8765 \
       --profile $profile \
       --rate-limit 20 \
       --output smoke_$profile.json \
       --md smoke_$profile.md
   done
   ```

3. Verify per-profile expectations:

   | Profile | Expected to find |
   |---|---|
   | quick | xss, headers, at least 1 sqli attempt |
   | recon | robots.txt missing, no security.txt |
   | auth | session cookie flags, login CSRF |
   | injection | reflected XSS (via `q`) |
   | authz | idor (via `id=1`), missing_auth (via `/admin`) |
   | config | headers missing (CSP, HSTS, XFO) |

4. Run with all optional features:

   ```bash
   python webprobe.py http://127.0.0.1:8765 \
     --profile owasp \
     --redact \
     --sarif --sarif-path smoke.sarif \
     --ledger smoke.ledger \
     --rate-limit 20 \
     --output smoke_full.json
   ```

5. Verify SARIF parses: `python -c "import json; json.load(open('smoke.sarif'))"`
6. Verify ledger verifies: `python -c "from webprobe.core.ledger import Ledger; assert Ledger('smoke.ledger').verify()"`

## Phase 4 acceptance criteria

- Every profile exits with code 0 (unless findings exceed `--fail-on`)
- `smoke_quick.json` contains at least one `xss` and one `headers` finding
- `smoke_authz.json` contains `idor` and `missing_auth`
- `smoke_full.json` has CVSS and taxonomy populated on every finding
- `smoke.sarif` parses as valid JSON
- `smoke.ledger` verifies as intact
- Commit message: `phase-4: smoke test against vulnerable localhost fixture`

## STOP condition

If any profile produces `0 findings` where the fixture table predicts ≥1, the
corresponding check has a bug. STOP and report which check didn't fire.

---

# Phase 5 — Staged rollout against the real target

**This phase only runs after Phases 0–4 all pass.**

Each stage is gated: do not proceed to stage N+1 until stage N has a clean,
reviewed output. If any stage produces unexpected behavior (crash, no findings
where expected, hostile response), stop and review before continuing.

## Stage A — Passive only (no active payloads)

```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile recon \
  --rate-limit 5 \
  --aimd \
  --output rollout_A.json \
  --md rollout_A.md
```

**Gate:** no 5xx rate > 5%, no rate-limit challenges (429), crawl completes
within 3 minutes.

---

## Stage B — Passive + unauthenticated active

```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile owasp \
  --rate-limit 3 \
  --aimd \
  --redact \
  --output rollout_B.json \
  --md rollout_B.md \
  --sarif --sarif-path rollout_B.sarif
```

**Gate:** no finding of `severity="critical"` in `headers` or `session`
categories is a false positive (review the top 10 by severity manually).

---

## Stage C — Authenticated (single identity)

```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile auth,authz \
  --rate-limit 3 \
  --aimd \
  --redact \
  --output rollout_C.json \
  --ledger rollout_C.ledger
```

**Gate:** no findings that would break the test account (e.g. successful
password change with `--test-password-change`). If any destructive action is
flagged, verify the test account's state before Stage D.

---

## Stage D — Full OWASP, detection only

```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile full \
  --rate-limit 3 \
  --aimd \
  --redact \
  --output rollout_D.json \
  --md rollout_D.md \
  --sarif --sarif-path rollout_D.sarif \
  --ledger rollout_D.ledger
```

**Not included:** `--exploit`, `--exploit-rce`, `--race-url`, `--otp-test`,
`--stored-xss`, `--second-order`, `--csrf-submit`. These are all opt-in and
must be a separate Stage E on written confirmation.

**Gate:** the report is reviewed by a human. False positives documented.
Client sign-off on the detection-only report.

---

## Stage E — Exploit chains (only with explicit sign-off)

```bash
python webprobe.py --config config/agraskbagheltourandtravels.json \
  --profile exploit \
  --exploit \
  --race-url "<URL from Stage D finding>" \
  --race-data '<body>' \
  --race-count 30 --race-expect 1 \
  --rate-limit 2 \
  --output rollout_E.json \
  --ledger rollout_E.ledger
```

**Not included in Stage E:** `--exploit-rce`. RCE proof is Stage F only.

**Gate:** every exploit finding is reproducible. The client is informed of
the exact window and the exact requests before Stage E runs.

---

## Stage F — RCE proof (only against staging, only with written approval)

```bash
# This runs a command on the server. Only against staging. Only with the
# client's written authorization visible in the session.
python webprobe.py --config config/agraskbagheltourandtravels_staging.json \
  --exploit --exploit-rce --rce-command "id" \
  --rate-limit 1 \
  --output rollout_F.json
```

**Gate:** evidence shows the exact output of `id`. Credentials rotated
post-test. Client receives the proof in the same session.

---

## Phase 5 acceptance criteria

- Stages A through D complete with a reviewed report
- Stage E runs only after Stage D sign-off
- Stage F runs only after Stage E is documented and stage environment confirmed
- Every stage has a corresponding `rollout_<X>.json` + `rollout_<X>.ledger`
- Commit message per stage: `phase-5-stage-X: <stage name> against <target>`

---

# Rollback procedures

If a phase fails at any point:

## Rollback a single file (Phase 3)

```bash
git checkout HEAD~1 -- webprobe/core/<file>.py
pytest tests/ -v
```

## Rollback a phase (any phase)

```bash
git reset --hard <commit-before-phase>
pytest tests/ -v
```

## Rollback a stage (Phase 5)

Phase 5 doesn't mutate code, only produces output files. "Rollback" means
discarding the output and rerunning at a lower stage. No git action needed.

---

# Reporting contract

After every phase, the agent delivers:

```markdown
## Phase <N> report

**Status:** PASS | FAIL | BLOCKED

**Files changed:**
- <path> — <one line describing what changed>

**Tests:**
- Total: <X>
- Passed: <Y>
- Failed: <Z> (list below if any)

**Acceptance criteria:**
- [x] Criterion 1
- [x] Criterion 2
- [ ] Criterion 3 — REASON: <why it's not met>

**Commit:** <hash> <message>

**Anomalies:** <anything unexpected, even if handled>

**Next phase readiness:** yes | no — <reason>
```

A phase is only "done" when its report is submitted and Status is PASS.

---

# Absolute stop conditions

The agent must STOP and wait for human input if any of the following occur:

1. `webprobe.py --self-check` cannot run at all (structural failure)
2. Any phase-3 rewrite requires changing a public function signature
3. Any phase-4 profile produces 0 findings where the fixture table predicts ≥1
4. Phase 5 Stage A hits > 5% 5xx responses or persistent 429s
5. Any test suite has non-zero failures that weren't there at the start of
   the phase
6. A fix seems to require touching a file outside the current phase's scope
7. The agent cannot determine the correct behavior from the protocol

In each case, the agent reports the exact condition and waits.
