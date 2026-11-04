"""Maps each check to CWE ID, OWASP Top 10:2021, and PCI-DSS v4.0 requirement."""

from typing import Dict, List


MAPPING: Dict[str, Dict] = {
    # Phase 1 — recon
    "robots":         {"cwe": "CWE-200", "owasp": "A01:2021", "pci": ["6.5.1"], "title": "Information Exposure"},
    "security_txt":   {"cwe": "CWE-200", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "Security.txt disclosure"},
    "infra":          {"cwe": "CWE-200", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "Infrastructure fingerprinting"},
    "methods":        {"cwe": "CWE-749", "owasp": "A05:2021", "pci": ["6.5.6"], "title": "Dangerous HTTP methods"},
    "js":             {"cwe": "CWE-540", "owasp": "A01:2021", "pci": ["6.5.1"], "title": "Source code / secret leak"},
    "discover":       {"cwe": "CWE-200", "owasp": "A01:2021", "pci": ["6.5.1"], "title": "Path exposure"},
    "graphql":        {"cwe": "CWE-200", "owasp": "A01:2021", "pci": ["6.5.1"], "title": "Introspection enabled"},
    "params":         {"cwe": "CWE-20",  "owasp": "A03:2021", "pci": ["6.5.1"], "title": "Undocumented parameter"},
    "payment_keys":   {"cwe": "CWE-798", "owasp": "A07:2021", "pci": ["3.6.1"], "title": "Hard-coded credentials"},
    "vhost":          {"cwe": "CWE-200", "owasp": "A01:2021", "pci": ["6.5.1"], "title": "Virtual host exposure"},

    # Phase 2 — auth
    "session":        {"cwe": "CWE-1004","owasp": "A07:2021", "pci": ["6.5.6"], "title": "Insecure session cookie"},
    "jwt":            {"cwe": "CWE-347", "owasp": "A02:2021", "pci": ["6.5.6"], "title": "JWT cryptographic weakness"},
    "jwt_exp":        {"cwe": "CWE-613", "owasp": "A07:2021", "pci": ["8.2.8"], "title": "Session expiry"},
    "jwt_pii":        {"cwe": "CWE-359", "owasp": "A02:2021", "pci": ["3.4.1"], "title": "PII in token"},
    "enum":           {"cwe": "CWE-204", "owasp": "A07:2021", "pci": ["6.5.1"], "title": "User enumeration"},
    "bruteforce":     {"cwe": "CWE-307", "owasp": "A07:2021", "pci": ["8.1.6"], "title": "No rate limiting"},
    "default_creds":  {"cwe": "CWE-1392","owasp": "A07:2021", "pci": ["2.2.1"], "title": "Default credentials"},
    "reset_token":    {"cwe": "CWE-330", "owasp": "A02:2021", "pci": ["8.3.6"], "title": "Weak reset token"},
    "reset_host":     {"cwe": "CWE-601", "owasp": "A03:2021", "pci": ["6.5.1"], "title": "Host header injection in reset"},
    "session_fix":    {"cwe": "CWE-384", "owasp": "A07:2021", "pci": ["6.5.6"], "title": "Session fixation"},
    "logout":         {"cwe": "CWE-613", "owasp": "A07:2021", "pci": ["6.5.6"], "title": "Session not invalidated on logout"},
    "login_csrf":     {"cwe": "CWE-352", "owasp": "A01:2021", "pci": ["6.5.9"], "title": "Login CSRF"},
    "logout_csrf":    {"cwe": "CWE-352", "owasp": "A01:2021", "pci": ["6.5.9"], "title": "Logout CSRF"},
    "auth_change_csrf": {"cwe": "CWE-352","owasp": "A01:2021", "pci": ["6.5.9"], "title": "Auth-change CSRF"},
    "mfa_presence":   {"cwe": "CWE-287", "owasp": "A07:2021", "pci": ["8.4.1"], "title": "MFA presence"},
    "mfa_bypass":     {"cwe": "CWE-287", "owasp": "A07:2021", "pci": ["8.4.1"], "title": "MFA bypass"},
    "otp_bruteforce": {"cwe": "CWE-307", "owasp": "A07:2021", "pci": ["8.4.2"], "title": "OTP brute-force"},
    "supabase":       {"cwe": "CWE-284", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Supabase misconfiguration"},
    "password_change":{"cwe": "CWE-620", "owasp": "A07:2021", "pci": ["8.3.1"], "title": "Password change without current password"},
    "email_change":   {"cwe": "CWE-620", "owasp": "A07:2021", "pci": ["8.3.1"], "title": "Email change without verification"},
    "password_policy":{"cwe": "CWE-521", "owasp": "A07:2021", "pci": ["8.3.6"], "title": "Weak password policy"},
    "cache_ctrl":     {"cwe": "CWE-525", "owasp": "A04:2021", "pci": ["6.5.3"], "title": "Missing no-store on authenticated"},
    "token_url":      {"cwe": "CWE-598", "owasp": "A04:2021", "pci": ["6.5.3"], "title": "Token in URL"},
    "remember_me":    {"cwe": "CWE-522", "owasp": "A07:2021", "pci": ["8.2.1"], "title": "Weak remember-me"},
    "session_conc":   {"cwe": "CWE-613", "owasp": "A07:2021", "pci": ["8.2.8"], "title": "Concurrent sessions"},
    "session_revoke": {"cwe": "CWE-613", "owasp": "A07:2021", "pci": ["8.2.8"], "title": "Session revocation"},
    "oauth":          {"cwe": "CWE-601", "owasp": "A07:2021", "pci": ["6.5.6"], "title": "OAuth misconfiguration"},

    # Phase 3 — injection
    "sqli":           {"cwe": "CWE-89",  "owasp": "A03:2021", "pci": ["6.2.4"], "title": "SQL injection"},
    "nosql":          {"cwe": "CWE-943", "owasp": "A03:2021", "pci": ["6.2.4"], "title": "NoSQL injection"},
    "xss":            {"cwe": "CWE-79",  "owasp": "A03:2021", "pci": ["6.5.7"], "title": "Cross-site scripting"},
    "ssti":           {"cwe": "CWE-1336","owasp": "A03:2021", "pci": ["6.2.4"], "title": "Template injection"},
    "cmdi":           {"cwe": "CWE-78",  "owasp": "A03:2021", "pci": ["6.2.4"], "title": "Command injection"},
    "lfi":            {"cwe": "CWE-22",  "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Path traversal"},
    "ssrf":           {"cwe": "CWE-918", "owasp": "A10:2021", "pci": ["6.5.1"], "title": "SSRF"},
    "proto":          {"cwe": "CWE-1321","owasp": "A03:2021", "pci": ["6.2.4"], "title": "Prototype pollution"},
    "crlf":           {"cwe": "CWE-113", "owasp": "A03:2021", "pci": ["6.5.1"], "title": "CRLF injection"},
    "upload":         {"cwe": "CWE-434", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Unrestricted upload"},
    "csp":            {"cwe": "CWE-79",  "owasp": "A03:2021", "pci": ["6.5.7"], "title": "Weak CSP"},
    "host_inject":    {"cwe": "CWE-20",  "owasp": "A03:2021", "pci": ["6.5.1"], "title": "Host header injection"},
    "mass_assign":    {"cwe": "CWE-915", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Mass assignment"},
    "json_type":      {"cwe": "CWE-20",  "owasp": "A03:2021", "pci": ["6.5.1"], "title": "JSON type confusion"},
    "blind_sqli":     {"cwe": "CWE-89",  "owasp": "A03:2021", "pci": ["6.2.4"], "title": "Blind SQL injection"},
    "xss_ast":        {"cwe": "CWE-79",  "owasp": "A03:2021", "pci": ["6.5.7"], "title": "Context-aware XSS"},

    # Phase 4 — authorization
    "idor":           {"cwe": "CWE-639", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "IDOR / BOLA"},
    "authz":          {"cwe": "CWE-285", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Missing authorization"},
    "forced":         {"cwe": "CWE-425", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Forced browsing"},
    "ui_only":        {"cwe": "CWE-602", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Client-side-only authz"},
    "role_tamper":    {"cwe": "CWE-269", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Privilege escalation"},
    "missing_auth":   {"cwe": "CWE-306", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Missing authentication"},
    "method_tamper":  {"cwe": "CWE-749", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Method-level authz"},
    "graphql_authz":  {"cwe": "CWE-285", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "GraphQL authz"},
    "rbac_matrix":    {"cwe": "CWE-285", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "RBAC gap"},

    # Phase 5 — business logic
    "business":       {"cwe": "CWE-840", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Business logic flaw"},
    "price":          {"cwe": "CWE-472", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Price tampering"},
    "race":           {"cwe": "CWE-362", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Race condition"},
    "webhook":        {"cwe": "CWE-347", "owasp": "A08:2021", "pci": ["6.5.1"], "title": "Unsigned webhook"},
    "razorpay":       {"cwe": "CWE-347", "owasp": "A08:2021", "pci": ["6.5.1"], "title": "Payment signature bypass"},
    "idempotency":    {"cwe": "CWE-837", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Missing idempotency"},
    "coupon":         {"cwe": "CWE-472", "owasp": "A04:2021", "pci": ["6.5.1"], "title": "Coupon abuse"},

    # Phase 6 — misconfig / infra
    "headers":        {"cwe": "CWE-693", "owasp": "A05:2021", "pci": ["6.5.10"], "title": "Missing security header"},
    "files":          {"cwe": "CWE-538", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "Exposed file"},
    "cors":           {"cwe": "CWE-942", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "CORS misconfiguration"},
    "cache":          {"cwe": "CWE-525", "owasp": "A05:2021", "pci": ["6.5.3"], "title": "Cache poisoning"},
    "smuggle":        {"cwe": "CWE-444", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "HTTP request smuggling"},
    "tls":            {"cwe": "CWE-326", "owasp": "A02:2021", "pci": ["4.2.1"], "title": "Weak TLS"},
    "cookie":         {"cwe": "CWE-1004","owasp": "A05:2021", "pci": ["6.5.6"], "title": "Cookie scope"},
    "cve":            {"cwe": "CWE-1035","owasp": "A06:2021", "pci": ["6.2.4"], "title": "Known CVE"},
    "debug":          {"cwe": "CWE-215", "owasp": "A05:2021", "pci": ["6.5.1"], "title": "Debug endpoint"},
    "cache_deception":{"cwe": "CWE-525", "owasp": "A05:2021", "pci": ["6.5.3"], "title": "Web cache deception"},
    "react2shell":    {"cwe": "CWE-502", "owasp": "A08:2021", "pci": ["6.2.4"], "title": "Deserialization RCE"},
    "nextjs-mw":      {"cwe": "CWE-285", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "Middleware bypass"},
    "supabase-rls":   {"cwe": "CWE-284", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "RLS bypass"},
    "supabase-rpc":   {"cwe": "CWE-284", "owasp": "A01:2021", "pci": ["6.5.8"], "title": "RPC over-exposure"},
}


def lookup(category: str) -> Dict:
    return MAPPING.get(category.lower(), {
        "cwe": "CWE-693", "owasp": "A05:2021", "pci": [], "title": category,
    })


def compliance_notes(category: str) -> List[str]:
    entry = lookup(category)
    notes = [f"CWE: {entry['cwe']}", f"OWASP: {entry['owasp']}"]
    if entry.get("pci"):
        notes.append(f"PCI-DSS v4.0: {', '.join(entry['pci'])}")
    return notes
