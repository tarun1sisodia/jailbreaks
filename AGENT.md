# `webprobe` — agent context

## 1. What this is

Single-file, zero-dependency Python 3.8+ command-line tool that crawls a web application and runs security checks organized into six phases (recon → auth → injection → authorization → business logic → misconfiguration). Built for **authorized** testing against provisioned test accounts. Every finding carries a phase number, severity, evidence string, and remediation.

Run: `./webprobe.py <url> --profile <name> [flags]`

## 2. Hard invariants — do not violate

- **One file.** Everything lives in `webprobe.py`. No imports outside the standard library.
- **Every check returns `List[Finding]`.** No exceptions, no `None`, no raising. A check that cannot test its target returns `[]` or a `Finding` with `confidence="low"` and `severity="info"` explaining why.
- **`Ctx` is the shared state bus.** Checks read from it (`ctx.pages`, `ctx.discovered`, `ctx.endpoints`, `ctx.tokens`, `ctx.tech`, `ctx.http`, `ctx.collab`) and must never mutate the HTTP client's configuration.
- **`ctx.http` is the single HTTP client.** Per-request abort and rate limiting live inside `HttpClient.fetch`. New code must go through `ctx.http.fetch()` or `ctx.http.clone()` — never `urllib` directly, never raw sockets except in explicitly raw probes (`raw_request`, `last_byte_sync`).
- **`HttpClient.fetch` is a wrapper.** Real logic is in `_fetch_inner`. The wrapper handles abort, throttle, and instability observation. If you edit the fetch path, edit `_fetch_inner`.
- **Activity log is append-only TSV.** Timestamp, test ID, outcome, description, evidence. Never rewrite previous rows.
- **Registries are declaration-only.** A check is registered by adding `name: (phase, function)` to `GLOBAL_EARLY`, `GLOBAL_LATE`, or `POINT_CHECKS`. No other mechanism.

## 3. Registry ordering — the rule that keeps breaking

The correct order at module scope is:

```
1. All check functions defined
2. GLOBAL_EARLY dict literal
3. GLOBAL_LATE dict literal
4. POINT_CHECKS dict literal
5. All GLOBAL_EARLY.update({...}), GLOBAL_LATE.update({...}), POINT_CHECKS.update({...})
6. PHASE_2_CHECKS = {...}         (and any other phase sets)
7. ALL_CHECKS = sorted(set(...))  -- MUST be after all .update() calls
8. PROFILES = {...}               -- MUST be after ALL_CHECKS exists
```

The current patch history violates this: `ALL_CHECKS` was computed before some `.update()` calls. That is the single most likely cause of the first import failure.

## 4. Registry semantics

- **`GLOBAL_EARLY`** — run once, before crawl. Used for header checks, TLS, CORS, cookie audit, anything that only needs `ctx.base_url`.
- **`GLOBAL_LATE`** — run once, after crawl. Used for anything that needs `ctx.pages`, `ctx.discovered`, `ctx.endpoints`, or a login form.
- **`POINT_CHECKS`** — run per injection point (per query parameter and per form field). Threaded. Every check takes `(ctx, point)`.

A check belongs in `GLOBAL_LATE` unless it is genuinely per-parameter. Putting a global check in `POINT_CHECKS` multiplies its request count by the number of injection points and will get the run rate-limited.

## 5. Phase numbering — approximate, needs an audit

`Finding.phase` does not consistently match the playbook phase. Known drift:

- `authz` (registered phase 2) is playbook Phase 4
- `payment_tamper` (registered phase 4) is playbook Phase 5
- `check_error_leak`, `check_verbose_api` (registered phase 4) are playbook Phase 6

The agent must audit `Finding.phase` for every check against the playbook before the first real report. The `--md` report groups by `Finding.phase`, so drift produces a report whose sections don't match the engagement's deliverables matrix.

## 6. Check inventory (as of end of Phase 5 patches)

| Playbook phase | Checks | Registry |
|---|---|---|
| 1 Recon | `robots`, `security_txt`, `infra`, `methods`, `wayback`, `js`, `discover`, `graphql`, `params` | `GLOBAL_EARLY` + `GLOBAL_LATE` |
| 2 Auth | `session`, `jwt`, `jwt_exp`, `jwt_pii`, `remember_me`, `password_policy`, `enum`, `bruteforce`, `default_creds`, `reset_token`, `reset_host`, `session_fix`, `logout`, `session_conc`, `token_url`, `cache_ctrl`, `login_csrf`, `logout_csrf`, `auth_change_csrf`, `mfa_presence`, `mfa_bypass`, `otp_bruteforce`, `supabase`, `password_change`, `email_change`, `csrf`, `ratelimit` | mixed |
| 3 Injection | `sqli`, `sqli_union`, `sqli_stacked`, `sqli_2nd`, `nosql`, `nosql_types`, `nosql_authbypass`, `xss`, `xss_stored`, `xss_dom`, `csp`, `ssti`, `cmdi`, `lfi`, `ssrf`, `proto`, `upload`, `crlf`, `host_inject`, `mass_assign`, `json_type`, `graphql_depth` | mixed |
| 4 Authz | `idor`, `idor_resources`, `forced`, `authz`, `staff_to_admin`, `ui_only`, `role_tamper`, `missing_auth`, `method_tamper`, `graphql_authz`, `verbose_api`, `error_leak`, `workflow`, `state_trans`, `refund_authz`, `tenant`, `coupon_authz`, `mass_assign_implicit`, `supabase_storage`, `payment_tamper` | mixed |
| 5 Business | `price`, `discount_stack`, `coupon_rules`, `coupon_enum`, `coupon_tamper`, `booking_ref`, `idempotency`, `webhook`, `test_live_keys`, `session_swap`, `cart_storage`, `business_rate` | mixed |
| 6 Misconfig | `headers`, `cors`, `files`, `cache`, `smuggle`, `cve` — **incomplete** | mixed |

## 7. Functions redefined across patches — resolve on assembly

| Function | Original | Redefined in | Resolution |
|---|---|---|---|
| `check_cors` | full v2 | Phase 4 completion | Use Phase 4 version (per-route) |
| `check_price` | full v2 | Phase 5 | Use Phase 5 version |
| `check_webhook` | full v2 | Phase 5 | Use Phase 5 version |
| `check_authz_customer` | Phase 2 | Phase 4 completion | Use Phase 4 version |
| `get_authed_client` | Phase 2 | Phase 4 completion | Use Phase 4 version (honors `--cookie`) |
| `check_supabase` | Phase 2 | Phase 4 completion (RPC block only) | Merge, Phase 4 RPC block wins |
| `check_idor` | full v2 | Phase 4 (partial edit — severity lines) | Merge |
| `HttpClient.fetch` | full v2 | Phase 2 completion (split to `fetch` + `_fetch_inner`) | Split wins |

## 8. CLI flag surface

Organizational: `--profile`, `--checks`, `--phase`, `--list-checks`, `--self-check` *(to be added in assembly)*

Targeting: `url`, `--cookie`, `--secondary-cookie`, `--staff-cookie`, `--admin-cookie`, `--header`, `--insecure`, `--timeout`, `--delay`

Operational gates: `--rate-limit`, `--testing-hours`, `--abort-file`, `--activity-log`, `--instability-threshold`, `--instability-samples`

Test account: `--test-email`, `--test-password`, `--admin-login`

Per-check opt-ins: `--time-based`, `--stored-xss`, `--second-order`, `--csrf-submit`, `--rate-test`, `--otp-test`, `--test-password-change`, `--password-policy-test`, `--param-discovery`, `--wayback`, `--coupon-enum`, `--idempotency-test`, `--business-rate-test`

Targeting (phase 4–5): `--state-url`, `--state-actions`, `--refund-url`, `--race-url`, `--race-data`, `--race-count`, `--race-expect`, `--webhook-url`, `--test-coupon`, `--expired-coupon`, `--ineligible-coupon`, `--tenant-param`, `--tenant-a`, `--tenant-b`

Infra: `--collab-host`, `--output`, `--md`, `--fail-on`, `-v`

## 9. Operational safety — non-negotiable

- **Rate limit and testing window** are enforced by `HttpClient._throttle` and `in_testing_window`. Never bypass them.
- **Abort file** — if the path exists, next fetch raises `SystemExit(3)`. `main()` must catch it and exit cleanly (report `130` or `3`).
- **Instability threshold** — if 5xx response rate exceeds `--instability-threshold` after `--instability-samples` responses, the run aborts phase 2–6 checks and logs it. Do not silently ignore.
- **`--test-password-change`** is destructive and prints the new password into evidence. Never enable by default; never enable against production.
- **`--admin-login`** sends default credentials. Never enable unless the admin surface is in the asset register and explicitly approved.

## 10. Known false-positive risks

- `check_params` — flags any parameter that changes response shape. The random control param must remain in place; verify it fires before trusting the finding.
- `check_session` entropy — flags short numeric session IDs. Short is not always weak; confirm against the app's actual token length.
- `check_test_live_keys` — matches `AIza...` Google keys, many of which are *supposed* to be public (Maps). Suppress unless the key has a matching server-side secret leak.
- `check_mass_assignment` — reports only when the field is reflected. Silent writes are missed; `check_mass_assignment_implicit` covers those.
- `check_idor` sequential detection — any endpoint returning distinct records on adjacent IDs is flagged. Confirm the records actually belong to different owners before reporting.
- `check_idor_resources` — if only one identity has seeded resources, the check is skipped. Seed at least one resource per identity.

## 11. Assembly procedure (the immediate next task)

1. **Create a clean `webprobe.py`** — combine full v2 base, then apply patches in order: P1 completion → P2 → P2 completion → P3 → P4 → P4 completion → P5.
2. **For each redefinition in §7**, keep only the latest version. Delete the earlier one.
3. **Move all `.update()` registry calls** above `ALL_CHECKS = sorted(...)` and `PROFILES = {...}`.
4. **Run `python3 -m py_compile webprobe.py`** — fix any import-time `NameError`.
5. **Add `--self-check` mode** that:
   - Imports the module
   - Iterates `ALL_CHECKS`, confirming each name resolves to a callable in one of the three registries
   - Confirms every `Finding.phase` value is in `[1,2,3,4,5,6]`
   - Confirms every `PROFILES[name]` entry exists in `ALL_CHECKS`
   - Exits `0` on success, `1` on any inconsistency, printing the specific failure
6. **Run `./webprobe.py --self-check`** — must exit 0.
7. **Smoke test against `python3 -m http.server`** — `--profile quick`, confirm no crashes. All findings will be low/info; that is expected.
8. **Commit.** Only after this does Phase 6 land.

## 12. Extension protocol — how to add a new check

1. Define `def check_<name>(ctx[, point]) -> List[Finding]` in the appropriate section of the file.
2. Decide phase number from the playbook, not from the existing code.
3. Register in `GLOBAL_EARLY`, `GLOBAL_LATE`, or `POINT_CHECKS` — pick based on whether the check needs crawl data.
4. Add the name to `PHASE_2_CHECKS` if it requires test credentials.
5. Add the name to any relevant `PROFILES` lists.
6. If the check is opt-in, add a `--<name>` flag and gate the body on `ctx.args.<name>`.
7. Add it to `--list-checks` output ordering.
8. Update §6 of this guide.

## 13. Phase 6 gaps (after assembly lands)

Still to implement:

- **A6** Permissions-Policy audit
- **B1–B3** TLS version, cipher suites, certificate chain/expiry — via `ssl.SSLContext` + `socket` inspection
- **B4** explicit HTTP→HTTPS redirect test
- **B5** mixed content scan across crawled pages
- **D2** debug endpoint wordlist (`/debug`, `/__debug__`, `/actuator/*`, `/console`, `/trace`)
- **E2** directory listing detection (`Index of /`, autoindex patterns)
- **H1–H3** cookie Domain / Path / `__Host-` / `__Secure-` audit
- **G3** third-party script inventory + SRI presence
- **F1** environment separation leak (test keys in prod bundles)
- **F2** debug flag detection (`?debug=1`, `X-Debug` header)
- **F3/F4** Supabase `/auth/v1/settings`, `/auth/v1/signup`, open-signup detection

**Out of black-box scope — flag as manual:** F5 (Worker/Pages env vars), F6 (Render service config). These require provider dashboard access.

## 14. Manual-only items across all phases

Irreducible: A4 (P2 credential stuffing), B3/B5 (P2 reset email inspection), C3 (P2 timeouts over hours), E2/E4 (P2 OTP inbox), D5 (P4 RLS policy review), B1/B6 (P5 coupon reuse / race), C3/C5/C6 (P5 race / state / time), D1/D3/D6 (P5 processor cooperation), E4/E5 (P5 source IP / out-of-order), F2/F4 (P5 unpaid state / fee state), G5 (P5 expired checkout), H1–H4 (P5 email observation), D5 (P6 RLS), F5/F6 (P6 provider dashboards).

These must appear in the final report as **Blocked — requires [reason]** with the exact prerequisite, not as Pass.

