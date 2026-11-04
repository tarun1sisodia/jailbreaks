"""
Unified check registries and profile definitions for webprobe.
"""

from typing import Any, Callable, Dict, List, Tuple

from webprobe.checks.phase1_recon import (
    check_discovery,
    check_graphql,
    check_infra,
    check_js,
    check_methods,
    check_params,
    check_payment_keys,
    check_robots,
    check_security_txt,
    check_wayback,
)
from webprobe.checks.phase2_auth import (
    check_auth_change_csrf,
    check_bruteforce,
    check_cache_controls,
    check_concurrent_sessions,
    check_default_creds,
    check_email_change,
    check_enumeration,
    check_host_header_reset,
    check_jwt,
    check_jwt_expiry,
    check_jwt_pii,
    check_login_csrf,
    check_logout_csrf,
    check_logout_invalidation,
    check_mfa_bypass,
    check_mfa_presence,
    check_otp_bruteforce,
    check_password_change,
    check_password_policy,
    check_remember_me,
    check_reset_token,
    check_session,
    check_session_fixation,
    check_supabase,
    check_token_in_url,
)
from webprobe.checks.phase3_injection import (
    check_cmdi,
    check_crlf,
    check_csp_effective,
    check_graphql_depth,
    check_host_header_injection,
    check_json_types,
    check_lfi,
    check_mass_assignment,
    check_nosql,
    check_nosql_authbypass,
    check_nosql_types,
    check_proto,
    check_sqli,
    check_sqli_second_order,
    check_sqli_stacked,
    check_sqli_union,
    check_ssrf,
    check_ssti,
    check_upload,
    check_xss,
    check_xss_dom,
    check_xss_stored,
)
from webprobe.checks.phase4_authorization import (
    check_authz_customer,
    check_cors,
    check_coupon_authz,
    check_error_leak,
    check_forced_browsing,
    check_graphql_authz,
    check_idor,
    check_idor_resources,
    check_mass_assignment_implicit,
    check_method_tampering,
    check_missing_auth,
    check_payment_tampering,
    check_refund_authz,
    check_role_tampering,
    check_staff_to_admin,
    check_state_transitions,
    check_supabase_storage,
    check_tenant_boundary,
    check_ui_only_bypass,
    check_verbose_api,
    check_workflow_bypass,
)
from webprobe.checks.phase5_business_logic import (
    check_booking_ref,
    check_business_rate,
    check_callback_security,
    check_cart_storage,
    check_coupon_enum,
    check_coupon_rules,
    check_coupon_tamper,
    check_csrf,
    check_discount_stacking,
    check_duplicate_submit,
    check_idempotency,
    check_price,
    check_race,
    check_ratelimit,
    check_session_swap,
    check_test_live_keys,
    check_webhook,
)
from webprobe.checks.phase6_infra import (
    check_cache_poison,
    check_cookie_flags,
    check_cve,
    check_debug_endpoints,
    check_debug_flags,
    check_directory_listing,
    check_files,
    check_headers,
    check_mixed_content,
    check_permissions_policy,
    check_smuggling,
    check_third_party_scripts,
    check_tls_config,
)


# Global checks that run early (before crawling)
GLOBAL_EARLY: Dict[str, Tuple[int, Callable[..., Any]]] = {
    # Phase 6
    "headers": (6, check_headers),
    "cors": (6, check_cors),
    "files": (6, check_files),
    "cve": (6, check_cve),
    "cache": (6, check_cache_poison),
    "smuggle": (6, check_smuggling),
    "tls": (6, check_tls_config),
    "permissions": (6, check_permissions_policy),
    "debug_endpoints": (6, check_debug_endpoints),
    "directory_listing": (6, check_directory_listing),
    "debug_flags": (6, check_debug_flags),
    "third_party": (6, check_third_party_scripts),
    "mixed_content": (6, check_mixed_content),

    # Phase 1
    "robots": (1, check_robots),
    "security_txt": (1, check_security_txt),
    "infra": (1, check_infra),
    "methods": (1, check_methods),
    "wayback": (1, check_wayback),

    # Phase 2
    "session": (2, check_session),
    "jwt": (2, check_jwt),
    "jwt_exp": (2, check_jwt_expiry),
    "jwt_pii": (2, check_jwt_pii),
    "remember_me": (2, check_remember_me),
}

# Global checks that run after crawling (require crawled pages/discovered URLs)
GLOBAL_LATE: Dict[str, Tuple[int, Callable[..., Any]]] = {
    # Phase 1
    "js": (1, check_js),
    "discover": (1, check_discovery),
    "graphql": (1, check_graphql),
    "params": (1, check_params),
    "paykeys": (1, check_payment_keys),

    # Phase 2
    "password_policy": (2, check_password_policy),
    "enum": (2, check_enumeration),
    "bruteforce": (2, check_bruteforce),
    "default_creds": (2, check_default_creds),
    "reset_token": (2, check_reset_token),
    "reset_host": (2, check_host_header_reset),
    "session_fix": (2, check_session_fixation),
    "logout": (2, check_logout_invalidation),
    "session_conc": (2, check_concurrent_sessions),
    "token_url": (2, check_token_in_url),
    "cache_ctrl": (2, check_cache_controls),
    "authz": (2, check_authz_customer),
    "login_csrf": (2, check_login_csrf),
    "logout_csrf": (2, check_logout_csrf),
    "auth_change_csrf": (2, check_auth_change_csrf),
    "mfa_presence": (2, check_mfa_presence),
    "mfa_bypass": (2, check_mfa_bypass),
    "otp_bruteforce": (2, check_otp_bruteforce),
    "supabase": (2, check_supabase),
    "password_change": (2, check_password_change),
    "email_change": (2, check_email_change),

    # Phase 3
    "sqli_second_order": (3, check_sqli_second_order),
    "nosql_authbypass": (3, check_nosql_authbypass),
    "xss_stored": (3, check_xss_stored),
    "xss_dom": (3, check_xss_dom),
    "csp": (3, check_csp_effective),
    "upload": (3, check_upload),
    "host_header": (3, check_host_header_injection),
    "graphql_depth": (3, check_graphql_depth),

    # Phase 4
    "forced": (4, check_forced_browsing),
    "idor_resources": (4, check_idor_resources),
    "coupon_authz": (4, check_coupon_authz),
    "ui_only": (4, check_ui_only_bypass),
    "role_tamper": (4, check_role_tampering),
    "workflow": (4, check_workflow_bypass),
    "state_trans": (4, check_state_transitions),
    "refund_authz": (4, check_refund_authz),
    "tenant": (4, check_tenant_boundary),
    "missing_auth": (4, check_missing_auth),
    "method_tamper": (4, check_method_tampering),
    "graphql_authz": (4, check_graphql_authz),
    "error_leak": (4, check_error_leak),
    "verbose_api": (4, check_verbose_api),
    "staff_to_admin": (4, check_staff_to_admin),
    "supabase_storage": (4, check_supabase_storage),

    # Phase 5
    "coupon_rules": (5, check_coupon_rules),
    "coupon_enum": (5, check_coupon_enum),
    "coupon_tamper": (5, check_coupon_tamper),
    "booking_ref": (5, check_booking_ref),
    "duplicate_submit": (5, check_duplicate_submit),
    "callback": (5, check_callback_security),
    "idempotency": (5, check_idempotency),
    "webhook": (5, check_webhook),
    "test_live_keys": (5, check_test_live_keys),
    "session_swap": (5, check_session_swap),
    "cart_storage": (5, check_cart_storage),
    "business_rate": (5, check_business_rate),
    "csrf": (5, check_csrf),
}

# Parameter point checks that execute per injection point
POINT_CHECKS: Dict[str, Tuple[int, Callable[..., Any]]] = {
    # Phase 3
    "sqli": (3, check_sqli),
    "sqli_union": (3, check_sqli_union),
    "sqli_stacked": (3, check_sqli_stacked),
    "nosql": (3, check_nosql),
    "nosql_types": (3, check_nosql_types),
    "xss": (3, check_xss),
    "ssti": (3, check_ssti),
    "cmdi": (3, check_cmdi),
    "lfi": (3, check_lfi),
    "ssrf": (3, check_ssrf),
    "proto": (3, check_proto),
    "crlf": (3, check_crlf),
    "mass_assign": (3, check_mass_assignment),
    "json_types": (3, check_json_types),

    # Phase 4
    "idor": (4, check_idor),
    "payment_tamper": (4, check_payment_tampering),

    # Phase 5
    "price": (5, check_price),
    "discount_stack": (5, check_discount_stacking),
    "race": (5, check_race),
    "ratelimit": (5, check_ratelimit),
}

# Complete sorted check registry
ALL_CHECKS: List[str] = sorted(set(GLOBAL_EARLY) | set(GLOBAL_LATE) | set(POINT_CHECKS))

# Profile configurations
PROFILES: Dict[str, List[str]] = {
    "quick": [
        "headers", "files", "cors", "sqli", "xss", "ssti", "idor",
    ],
    "recon": [
        "headers", "robots", "security_txt", "infra", "methods",
        "js", "discover", "graphql", "params", "wayback", "paykeys", "cve",
    ],
    "auth": [
        "session", "jwt", "jwt_exp", "jwt_pii", "password_policy", "enum",
        "bruteforce", "default_creds", "reset_token", "reset_host",
        "session_fix", "logout", "login_csrf", "logout_csrf", "mfa_presence",
        "supabase",
    ],
    "injection": [
        "sqli", "sqli_union", "sqli_stacked", "sqli_second_order",
        "nosql", "nosql_types", "nosql_authbypass",
        "xss", "xss_stored", "xss_dom", "csp", "upload", "crlf",
        "cmdi", "lfi", "ssrf", "ssti", "proto",
    ],
    "authz": [
        "forced", "idor", "idor_resources", "authz", "ui_only",
        "role_tamper", "missing_auth", "method_tamper", "staff_to_admin",
        "supabase_storage",
    ],
    "business": [
        "price", "discount_stack", "coupon_rules", "coupon_authz",
        "booking_ref", "webhook", "test_live_keys", "payment_tamper",
        "csrf", "race", "ratelimit",
    ],
    "config": [
        "headers", "cors", "files", "cve", "cache", "smuggle",
        "tls", "permissions", "debug_endpoints", "directory_listing",
        "debug_flags", "third_party", "mixed_content",
    ],
    "owasp": [
        "headers", "cors", "session", "jwt", "sqli", "xss", "ssti", "cmdi", "lfi",
        "ssrf", "proto", "idor", "forced", "csrf", "files", "cache", "cve",
        "coupon_rules", "booking_ref", "test_live_keys", "webhook",
    ],
    "api": [
        "cors", "jwt", "graphql", "sqli", "nosql", "idor", "forced", "proto",
        "price", "ratelimit", "js", "params", "booking_ref", "test_live_keys",
        "webhook",
    ],
    "full": ALL_CHECKS,
}
