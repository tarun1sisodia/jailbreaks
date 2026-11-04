# Phase 0 Baseline Report

## Date: 2026-11-04
## Branch: `fix/phase6-integration`

### 1. Compilation Status (`baseline_compile.log`)
- Target: `webprobe.py` and all files under `webprobe/**/*.py`
- Failures: 0
- Status: All Python files compiled cleanly with `python -m py_compile`.

### 2. Self-Check Status (`baseline_selfcheck.log`)
- Command: `python webprobe.py --self-check`
- Result: **PASSED** (Exit code 0)
- Registered checks: 136 total checks registered
  - 33 early global checks
  - 81 late global checks
  - 22 point checks
  - 11 scan profiles (`quick`, `recon`, `auth`, `injection`, `authz`, `business`, `config`, `owasp`, `api`, `full`, `exploit`)

### 3. Existing Test Suite (`baseline_pytest.log`)
- Command: `python -m pytest -v`
- Total tests: 16
- Passed: 16
- Failed: 0
- Errored: 0

### 4. Summary & Known Deficiencies to Address in Phase 1
Although the initial compilation and 16 basic unit tests pass, the 10 known bugs documented in `AGENT_FIX_PROTOCOL.md` currently reside in the codebase:
1. `check_jwt_rs_hs_confusion`: `name` variable scope error when parsing from HTML (`NameError`).
2. `check_jwt_jku`: `name` variable scope error in loop body (`NameError`).
3. `check_session_revocation`: `r.links` attribute access failure (`AttributeError`).
4. `check_cors_dynamic`: f-string attribute parsing syntax incompatibility on Python < 3.12.
5. `check_rbac_matrix`: Tautological identical body comparison (`bodies[label][:500] == bodies[label][:500]`) flagging benign responses as IDOR.
6. `check_graphql_resolver`: Nested field bracket regex failing on modern GraphQL schemas.
7. `check_fsm_workflow`: Missing precondition state context resulting in false positives.
8. `check_numeric_precision`: Sentinel collision false positive on standard price values (`0.01`).
9. `exploits/postex.py`: Read-only proof generation returns template without executing invocation callback.
10. `checks/__init__.py`: Duplicate `ALL_CHECKS` sort ordering artifact.
