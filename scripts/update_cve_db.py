#!/usr/bin/env python3
"""Build or verify the passive CVE fingerprint database from NVD.

The runtime engine (backend/webprobe/checks/phase6_infra.py) reads
backend/webprobe/data/cve_fingerprints.json. This script keeps that file
in sync with the NVD 2.0 API for a curated watchlist.

Usage:
  python3 scripts/update_cve_db.py --check
  python3 scripts/update_cve_db.py --write
  python3 scripts/update_cve_db.py --write --refresh

NVD allows ~5 requests per 30 seconds without an API key; the script
sleeps between live requests and caches responses under
~/.cache/jailbreaks-nvd so repeated runs are cheap.

This tool only records version ranges. It never sends exploit traffic.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DB_PATH = REPO / "backend" / "webprobe" / "data" / "cve_fingerprints.json"
CACHE_DIR = Path.home() / ".cache" / "jailbreaks-nvd"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
RATE_LIMIT_SECONDS = 6.5


# ---------------------------------------------------------------------------
# Curated watchlist. A fingerprint groups CVEs that share a version banner.
# `cpes` limits NVD CPE matches to the real product (e.g. wordpress:wordpress)
# so unrelated Oracle/NetApp CPE entries do not pollute the ranges.
# `manual_ranges` is used when NVD has no usable range, and `extra_ranges`
# adds a range NVD omitted.
# ---------------------------------------------------------------------------
WATCHLIST = [
    {
        "product": "nginx",
        "source": "headers",
        "regex": r"(?i)nginx/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2021-23017",
                "severity": "high",
                "title": "nginx resolver off-by-one (CVE-2021-23017)",
                "cpes": ["f5:nginx"],
                "remediation": "Upgrade to nginx 1.20.1 or later.",
            },
            {
                "cve": "CVE-2019-20372",
                "severity": "medium",
                "title": "nginx error_page request smuggling (CVE-2019-20372)",
                "cpes": ["f5:nginx"],
                "remediation": "Upgrade to nginx 1.17.7 or later.",
            },
        ],
    },
    {
        "product": "Apache Tomcat",
        "source": "headers",
        "regex": r"(?i)Apache Tomcat/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2025-24813",
                "severity": "critical",
                "title": "Apache Tomcat partial PUT RCE / file disclosure (CVE-2025-24813)",
                "cpes": ["apache:tomcat"],
                "remediation": "Upgrade to Tomcat 9.0.99 / 10.1.35 / 11.0.3 or later; "
                               "disable partial PUT and default-servlet writes.",
            },
            {
                "cve": "CVE-2020-1938",
                "severity": "critical",
                "title": "Apache Tomcat AJP Ghostcat file read/inclusion (CVE-2020-1938)",
                "cpes": ["apache:tomcat"],
                "remediation": "Upgrade to Tomcat 7.0.100 / 8.5.51 / 9.0.31 or later; "
                               "disable the AJP connector or require a secret.",
            },
            {
                "cve": "CVE-2017-12615",
                "severity": "high",
                "title": "Apache Tomcat PUT JSP upload (CVE-2017-12615)",
                "cpes": ["apache:tomcat"],
                "extra_ranges": [
                    {"low": [8, 0, 0], "high": [8, 0, 44]},
                    {"low": [8, 5, 0], "high": [8, 5, 15]},
                    {"low": [9, 0, 0], "high": [9, 0, 0]},
                ],
                "remediation": "Upgrade to Tomcat 7.0.80 / 8.0.45 / 8.5.16 / "
                               "9.0.0.M22 or later; disable HTTP PUT.",
            },
        ],
    },
    {
        "product": "WordPress",
        "source": "body",
        "regex": r"(?i)WordPress\s+(\d+\.\d+(?:\.\d+)?)",
        "rules": [
            {
                "cve": "CVE-2022-21661",
                "severity": "high",
                "title": "WordPress WP_Query SQL injection (CVE-2022-21661)",
                "cpes": ["wordpress:wordpress"],
                "remediation": "Upgrade to WordPress 5.8.3 or the fixed release "
                               "for your branch.",
            },
            {
                "cve": "CVE-2022-21664",
                "severity": "high",
                "title": "WordPress SQL injection (CVE-2022-21664)",
                "cpes": ["wordpress:wordpress"],
                "remediation": "Upgrade to WordPress 5.8.3 or later.",
            },
            {
                "cve": "CVE-2019-8942",
                "severity": "high",
                "title": "WordPress post-meta RCE (CVE-2019-8942)",
                "cpes": ["wordpress:wordpress"],
                "extra_ranges": [
                    {"low": [5, 0, 0], "high": [5, 0, 1], "high_exclusive": True},
                ],
                "remediation": "Upgrade to WordPress 4.9.9 / 5.0.1 or later.",
            },
            {
                "cve": "CVE-2019-8943",
                "severity": "medium",
                "title": "WordPress wp_crop_image path traversal (CVE-2019-8943)",
                "cpes": ["wordpress:wordpress"],
                "remediation": "Upgrade to WordPress 5.0.4 or later.",
            },
            {
                "cve": "CVE-2020-28032",
                "severity": "high",
                "title": "WordPress deserialization issue (CVE-2020-28032)",
                "cpes": ["wordpress:wordpress"],
                "remediation": "Upgrade to WordPress 5.5.2 or later.",
            },
            {
                "cve": "CVE-2021-39201",
                "severity": "medium",
                "title": "WordPress editor XSS (CVE-2021-39201)",
                "cpes": ["wordpress:wordpress"],
                "manual_ranges": [
                    {"low": [0, 0, 0], "high": [5, 8, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to WordPress 5.8 or later.",
            },
            {
                "cve": "CVE-2023-2745",
                "severity": "medium",
                "title": "WordPress wp_lang directory traversal (CVE-2023-2745)",
                "cpes": ["wordpress:wordpress"],
                "extra_ranges": [
                    {"low": [6, 2, 0], "high": [6, 2, 0]},
                ],
                "remediation": "Upgrade to WordPress 6.2.1 or later.",
            },
            {
                "cve": "CVE-2024-31210",
                "severity": "high",
                "title": "WordPress plugin upload RCE (CVE-2024-31210)",
                "cpes": ["wordpress:wordpress"],
                "remediation": "Upgrade to WordPress 6.4.3 or later.",
            },
        ],
    },
    {
        "product": "Drupal",
        "source": "body",
        "regex": r"(?i)Drupal\s+(\d+(?:\.\d+){0,2})",
        "rules": [
            {
                "cve": "CVE-2018-7600",
                "severity": "critical",
                "title": "Drupalgeddon2 remote code execution (CVE-2018-7600)",
                "cpes": ["drupal:drupal"],
                "remediation": "Upgrade to Drupal 7.58 / 8.3.9 / 8.4.6 / 8.5.1 or later.",
            },
            {
                "cve": "CVE-2018-7602",
                "severity": "critical",
                "title": "Drupalgeddon2 follow-up RCE (CVE-2018-7602)",
                "cpes": ["drupal:drupal"],
                "remediation": "Upgrade to Drupal 7.59 / 8.4.8 / 8.5.3 or later.",
            },
            {
                "cve": "CVE-2019-6340",
                "severity": "critical",
                "title": "Drupal REST module RCE (CVE-2019-6340)",
                "cpes": ["drupal:drupal"],
                "remediation": "Upgrade to Drupal 8.5.11 / 8.6.10 or later.",
            },
            {
                "cve": "CVE-2020-13671",
                "severity": "high",
                "title": "Drupal uploaded-file MIME confusion (CVE-2020-13671)",
                "cpes": ["drupal:drupal"],
                "remediation": "Upgrade to Drupal 7.74 / 8.8.12 / 8.9.10 / 9.0.9 or later.",
            },
        ],
    },
    {
        "product": "Joomla",
        "source": "body",
        "regex": r"(?i)Joomla!?\s*(\d+\.\d+(?:\.\d+)?)",
        "rules": [
            {
                "cve": "CVE-2023-23752",
                "severity": "high",
                "title": "Joomla webservice access check bypass (CVE-2023-23752)",
                "cpes": ["joomla:joomla\\!"],
                "remediation": "Upgrade to Joomla 4.2.8 or later.",
            },
            {
                "cve": "CVE-2015-8562",
                "severity": "critical",
                "title": "Joomla PHP object injection RCE (CVE-2015-8562)",
                "manual_ranges": [
                    {"low": [1, 5, 0], "high": [3, 4, 5]},
                ],
                "remediation": "Upgrade to Joomla 3.4.6 or later.",
            },
        ],
    },
    {
        "product": "AngularJS",
        "source": "body",
        "regex": r"(?i)angular(?:\.min)?[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2020-7676",
                "severity": "medium",
                "title": "AngularJS sanitizer XSS (CVE-2020-7676)",
                "cpes": ["angularjs:angularjs"],
                "remediation": "Upgrade to AngularJS 1.8.0 or later.",
            },
            {
                "cve": "CVE-2019-14863",
                "severity": "medium",
                "title": "AngularJS XSS (CVE-2019-14863)",
                "cpes": ["angularjs:angularjs"],
                "remediation": "Upgrade to AngularJS 1.5.0-beta.0 or later.",
            },
        ],
    },
    {
        "product": "lodash",
        "source": "body",
        "regex": r"(?i)lodash[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2021-23337",
                "severity": "high",
                "title": "lodash template command injection (CVE-2021-23337)",
                "cpes": ["lodash:lodash"],
                "remediation": "Upgrade to lodash 4.17.21 or later.",
            },
            {
                "cve": "CVE-2020-8203",
                "severity": "high",
                "title": "lodash prototype pollution (CVE-2020-8203)",
                "cpes": ["lodash:lodash"],
                "remediation": "Upgrade to lodash 4.17.20 or later.",
            },
            {
                "cve": "CVE-2019-10744",
                "severity": "high",
                "title": "lodash prototype pollution (CVE-2019-10744)",
                "cpes": ["lodash:lodash"],
                "remediation": "Upgrade to lodash 4.17.12 or later.",
            },
        ],
    },
    {
        "product": "Moment.js",
        "source": "body",
        "regex": r"(?i)moment(?:\.min)?[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2022-24785",
                "severity": "high",
                "title": "Moment.js path traversal (CVE-2022-24785)",
                "cpes": ["momentjs:moment"],
                "remediation": "Upgrade to Moment.js 2.29.2 or later.",
            },
            {
                "cve": "CVE-2022-31129",
                "severity": "high",
                "title": "Moment.js ReDoS (CVE-2022-31129)",
                "cpes": ["momentjs:moment"],
                "remediation": "Upgrade to Moment.js 2.29.4 or later.",
            },
        ],
    },
    {
        "product": "Handlebars",
        "source": "body",
        "regex": r"(?i)handlebars(?:\.min)?[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2021-23369",
                "severity": "critical",
                "title": "Handlebars RCE (CVE-2021-23369)",
                "cpes": ["handlebarsjs:handlebars"],
                "remediation": "Upgrade to Handlebars 4.7.7 or later.",
            },
            {
                "cve": "CVE-2019-19919",
                "severity": "critical",
                "title": "Handlebars prototype pollution RCE (CVE-2019-19919)",
                "manual_ranges": [
                    {"low": [0, 0, 0], "high": [4, 3, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to Handlebars 4.3.0 or later.",
            },
        ],
    },
    {
        "product": "Axios",
        "source": "body",
        "regex": r"(?i)axios[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2023-45857",
                "severity": "medium",
                "title": "Axios XSRF token leakage (CVE-2023-45857)",
                "manual_ranges": [
                    {"low": [1, 0, 0], "high": [1, 5, 1]},
                ],
                "remediation": "Upgrade to Axios 1.6.0 or later.",
            },
            {
                "cve": "CVE-2021-3749",
                "severity": "high",
                "title": "Axios ReDoS (CVE-2021-3749)",
                "cpes": ["axios:axios"],
                "remediation": "Upgrade to Axios 0.21.2 or later.",
            },
        ],
    },
    {
        "product": "DOMPurify",
        "source": "body",
        "regex": r"(?i)dompurify[-/.]?(?:v)?(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2024-45801",
                "severity": "high",
                "title": "DOMPurify nesting-based mXSS (CVE-2024-45801)",
                "cpes": ["cure53:dompurify"],
                "remediation": "Upgrade to DOMPurify 2.5.4 / 3.1.3 or later.",
            },
            {
                "cve": "CVE-2024-47875",
                "severity": "high",
                "title": "DOMPurify nesting-based mXSS (CVE-2024-47875)",
                "cpes": ["cure53:dompurify"],
                "remediation": "Upgrade to DOMPurify 2.5.0 / 3.1.3 or later.",
            },
        ],
    },
    {
        "product": "OpenSSL",
        "source": "headers",
        "regex": r"(?i)OpenSSL/(\d+\.\d+\.\d+[a-z]*)",
        "rules": [
            {
                "cve": "CVE-2022-0778",
                "severity": "high",
                "title": "OpenSSL BN_mod_sqrt infinite loop (CVE-2022-0778)",
                "manual_ranges": [
                    {"low": [1, 0, 2, 0], "high": [1, 0, 2, 679]},
                    {"low": [1, 1, 0, 0], "high": [1, 1, 1, 13]},
                    {"low": [3, 0, 0, 0], "high": [3, 0, 2, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to OpenSSL 1.0.2zd / 1.1.1n / 3.0.2 or later.",
            },
            {
                "cve": "CVE-2021-3711",
                "severity": "critical",
                "title": "OpenSSL SM2 decryption buffer overflow (CVE-2021-3711)",
                "manual_ranges": [
                    {"low": [1, 1, 1, 0], "high": [1, 1, 1, 12], "high_exclusive": True},
                ],
                "remediation": "Upgrade to OpenSSL 1.1.1l or later.",
            },
            {
                "cve": "CVE-2014-0160",
                "severity": "high",
                "title": "OpenSSL Heartbleed (CVE-2014-0160)",
                "manual_ranges": [
                    {"low": [1, 0, 1, 0], "high": [1, 0, 1, 6]},
                ],
                "remediation": "Upgrade to OpenSSL 1.0.1g or later.",
            },
        ],
    },
    {
        "product": "PHP",
        "source": "headers",
        "regex": r"PHP/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2025-1861",
                "severity": "critical",
                "title": "PHP redirect Location truncation (CVE-2025-1861)",
                "manual_ranges": [
                    {"low": [8, 1, 0, 0], "high": [8, 1, 32, 0], "high_exclusive": True},
                    {"low": [8, 2, 0, 0], "high": [8, 2, 28, 0], "high_exclusive": True},
                    {"low": [8, 3, 0, 0], "high": [8, 3, 19, 0], "high_exclusive": True},
                    {"low": [8, 4, 0, 0], "high": [8, 4, 5, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to PHP 8.1.32 / 8.2.28 / 8.3.19 / 8.4.5 or later.",
                "note": "NVD primary score is 9.8; the PHP CNA scores it 6.3 (medium). "
                        "NVD CPE upper bounds conflict with the vendor advisory, so the "
                        "vendor ranges are used here.",
            },
            {
                "cve": "CVE-2026-109618",
                "severity": "critical",
                "title": "PHP out-of-memory longjmp remote code execution (CVE-2026-109618)",
                "manual_ranges": [
                    {"low": [7, 3, 0, 0], "high": [8, 2, 35, 0], "high_exclusive": True},
                    {"low": [8, 3, 0, 0], "high": [8, 3, 36, 0], "high_exclusive": True},
                    {"low": [8, 4, 0, 0], "high": [8, 4, 27, 0], "high_exclusive": True},
                    {"low": [8, 5, 0, 0], "high": [8, 5, 12, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later.",
                "note": "CISA KEV: known exploited. Requires the PHP build to hit the "
                        "out-of-memory path; confirm the exact runtime configuration.",
            },
            {
                "cve": "CVE-2026-109619",
                "severity": "high",
                "title": "PHP stale global state remote code execution (CVE-2026-109619)",
                "manual_ranges": [
                    {"low": [5, 4, 0, 0], "high": [8, 2, 35, 0], "high_exclusive": True},
                    {"low": [8, 3, 0, 0], "high": [8, 3, 36, 0], "high_exclusive": True},
                    {"low": [8, 4, 0, 0], "high": [8, 4, 27, 0], "high_exclusive": True},
                    {"low": [8, 5, 0, 0], "high": [8, 5, 12, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later.",
                "note": "CISA KEV: known exploited. Version detection alone does not "
                        "prove the stale-state path is reachable.",
            },
        ],
    },
    {
        "product": "Next.js",
        "source": "headers",
        "regex": r"(?i)Next\.js/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2025-29927",
                "severity": "critical",
                "title": "Next.js middleware authorization bypass (CVE-2025-29927)",
                "manual_ranges": [
                    {"low": [11, 1, 4, 0], "high": [12, 3, 5, 0], "high_exclusive": True},
                    {"low": [13, 0, 0, 0], "high": [13, 5, 9, 0], "high_exclusive": True},
                    {"low": [14, 0, 0, 0], "high": [14, 2, 25, 0], "high_exclusive": True},
                    {"low": [15, 0, 0, 0], "high": [15, 2, 3, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to Next.js 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 "
                               "or later; block x-middleware-subrequest at the proxy if "
                               "patching is not possible.",
            },
            {
                "cve": "CVE-2025-55182",
                "severity": "critical",
                "title": "Next.js React Server Components RCE (CVE-2025-55182)",
                "manual_ranges": [
                    {"low": [15, 0, 0, 0], "high": [15, 0, 5, 0], "high_exclusive": True},
                    {"low": [15, 1, 0, 0], "high": [15, 1, 9, 0], "high_exclusive": True},
                    {"low": [15, 2, 0, 0], "high": [15, 2, 6, 0], "high_exclusive": True},
                    {"low": [15, 3, 0, 0], "high": [15, 3, 6, 0], "high_exclusive": True},
                    {"low": [15, 4, 0, 0], "high": [15, 4, 8, 0], "high_exclusive": True},
                    {"low": [15, 5, 0, 0], "high": [15, 5, 7, 0], "high_exclusive": True},
                    {"low": [15, 6, 0, 0], "high": [15, 6, 0, 0]},
                    {"low": [16, 0, 0, 0], "high": [16, 0, 7, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to the vendor-fixed release for your line: "
                               "14.2.35 / 15.0.8 / 15.1.12 / 15.2.9 / 15.3.9 / 15.4.11 "
                               "/ 15.5.10 / 16.0.11 / 16.1.5.",
                "note": "CISA KEV: known exploited. NVD ranges describe the initial "
                        "patches; the vendor note lists the final fixed releases.",
            },
            {
                "cve": "CVE-2026-64642",
                "severity": "high",
                "title": "Next.js i18n middleware authorization bypass (CVE-2026-64642)",
                "manual_ranges": [
                    {"low": [16, 0, 0, 0], "high": [16, 2, 11, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to Next.js 16.2.11 or later.",
            },
            {
                "cve": "CVE-2026-44578",
                "severity": "high",
                "title": "Next.js WebSocket upgrade SSRF (CVE-2026-44578)",
                "manual_ranges": [
                    {"low": [13, 4, 13, 0], "high": [15, 5, 16, 0], "high_exclusive": True},
                    {"low": [16, 0, 0, 0], "high": [16, 2, 5, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to Next.js 15.5.16 / 16.2.5 or later.",
            },
        ],
    },
    {
        "product": "ASP.NET Core",
        "source": "headers",
        "regex": r"(?i)(?:ASP\.NET Core|Kestrel)/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2025-55315",
                "severity": "critical",
                "title": "ASP.NET Core request smuggling (CVE-2025-55315)",
                "manual_ranges": [
                    {"low": [2, 3, 0, 0], "high": [2, 3, 6, 0], "high_exclusive": True},
                    {"low": [8, 0, 0, 0], "high": [8, 0, 21, 0], "high_exclusive": True},
                    {"low": [9, 0, 0, 0], "high": [9, 0, 10, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to ASP.NET Core 2.3.6 / 8.0.21 / 9.0.10 or later.",
            },
            {
                "cve": "CVE-2026-88092",
                "severity": "critical",
                "title": "ASP.NET Core request smuggling (CVE-2026-88092)",
                "manual_ranges": [
                    {"low": [8, 0, 0, 0], "high": [8, 0, 32, 0], "high_exclusive": True},
                    {"low": [9, 0, 0, 0], "high": [9, 0, 21, 0], "high_exclusive": True},
                    {"low": [10, 0, 0, 0], "high": [10, 0, 13, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to ASP.NET Core 8.0.32 / 9.0.21 / 10.0.13 or later.",
            },
            {
                "cve": "CVE-2026-26130",
                "severity": "high",
                "title": "ASP.NET Core denial of service (CVE-2026-26130)",
                "manual_ranges": [
                    {"low": [8, 0, 0, 0], "high": [8, 0, 25, 0], "high_exclusive": True},
                    {"low": [9, 0, 0, 0], "high": [9, 0, 14, 0], "high_exclusive": True},
                    {"low": [10, 0, 0, 0], "high": [10, 0, 4, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to ASP.NET Core 8.0.25 / 9.0.14 / 10.0.4 or later.",
            },
        ],
    },
    {
        "product": ".NET",
        "source": "headers",
        "regex": r"(?i)(?:\.NET|dotnet)/(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2026-111497",
                "severity": "critical",
                "title": "Brotli decoder RCE/DoS in .NET (CVE-2026-111497)",
                "manual_ranges": [
                    {"low": [8, 0, 0, 0], "high": [8, 0, 33, 0], "high_exclusive": True},
                    {"low": [9, 0, 0, 0], "high": [9, 0, 22, 0], "high_exclusive": True},
                    {"low": [10, 0, 0, 0], "high": [10, 0, 14, 0], "high_exclusive": True},
                ],
                "remediation": "Upgrade to .NET 8.0.33 / 9.0.22 / 10.0.14 or later.",
                "note": "CISA KEV: known exploited. Only applications that decode "
                        "attacker-controlled Brotli content are exposed.",
            },
            {
                "cve": "CVE-2024-43498",
                "severity": "critical",
                "title": ".NET 9.0.0 type confusion RCE (CVE-2024-43498)",
                "manual_ranges": [
                    {"low": [9, 0, 0, 0], "high": [9, 0, 0, 0]},
                ],
                "remediation": "Upgrade to .NET 9.0.1 or later.",
            },
        ],
    },
    {
        "product": "Atlassian Jira",
        "source": "body",
        "regex": r"(?i)(?:Atlassian Jira|jira\.version[^0-9]{0,40})\s*(\d+\.\d+\.\d+)",
        "rules": [
            {
                "cve": "CVE-2019-11581",
                "severity": "critical",
                "title": "Jira Server template injection (CVE-2019-11581)",
                "cpes": ["atlassian:jira_server"],
                "manual_ranges": [
                    {"low": [4, 4, 0], "high": [7, 6, 14], "high_exclusive": True},
                    {"low": [7, 7, 0], "high": [7, 13, 5], "high_exclusive": True},
                    {"low": [8, 0, 0], "high": [8, 0, 3], "high_exclusive": True},
                    {"low": [8, 1, 0], "high": [8, 1, 2], "high_exclusive": True},
                    {"low": [8, 2, 0], "high": [8, 2, 3], "high_exclusive": True},
                ],
                "remediation": "Upgrade to Jira Server 7.6.14 / 7.13.5 / 8.0.3 / "
                               "8.1.2 / 8.2.3 or later.",
            },
            {
                "cve": "CVE-2020-14179",
                "severity": "medium",
                "title": "Jira custom field/SLA information disclosure (CVE-2020-14179)",
                "cpes": ["atlassian:jira_server", "atlassian:jira_data_center"],
                "remediation": "Upgrade to Jira Server/Data Center 8.5.8 / 8.11.1 or later.",
            },
            {
                "cve": "CVE-2020-14181",
                "severity": "medium",
                "title": "Jira user enumeration (CVE-2020-14181)",
                "cpes": ["atlassian:jira_server", "atlassian:data_center", "atlassian:jira"],
                "remediation": "Upgrade to Jira Server/Data Center 7.13.6 / 8.5.7 / "
                               "8.12.0 or later.",
            },
        ],
    },
]


def parse_version(value: str) -> list[int]:
    parts = [int(p) for p in re.findall(r"\d+", value or "")[:4]]
    return parts or [0]


def fetch_cve(cve: str, refresh: bool = False) -> dict | None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / f"{cve}.json"
    if cache.exists() and not refresh:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except ValueError:
            cache.unlink()
    req = urllib.request.Request(
        NVD_URL.format(cve=cve),
        headers={"User-Agent": "jailbreaks-cve-db/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"  ! {cve}: {exc}", file=sys.stderr)
        return None
    cache.write_text(json.dumps(payload), encoding="utf-8")
    time.sleep(RATE_LIMIT_SECONDS)
    return payload


def nvd_ranges(payload: dict, cpes: list[str]) -> list[dict]:
    if not payload:
        return []
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return []
    cve = vulns[0].get("cve", {})
    out: list[dict] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if cpes and not any(f":{cpe}:" in criteria for cpe in cpes):
                    continue
                start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                exact = match.get("version")
                if not start and not end and not exact:
                    continue
                if exact and not start and not end:
                    out.append({"low": parse_version(exact), "high": parse_version(exact)})
                    continue
                if not end:
                    continue
                rng: dict = {
                    "low": parse_version(start) if start else [0, 0, 0],
                    "high": parse_version(end),
                }
                if match.get("versionStartExcluding"):
                    rng["low_exclusive"] = True
                if match.get("versionEndExcluding"):
                    rng["high_exclusive"] = True
                out.append(rng)
    # Deduplicate while preserving order.
    seen = set()
    unique = []
    for rng in out:
        key = json.dumps(rng, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(rng)
    return unique


def build_rule(rule: dict, refresh: bool) -> dict | None:
    cve = rule["cve"]
    payload = fetch_cve(cve, refresh=refresh)
    ranges = nvd_ranges(payload, rule.get("cpes", []))
    if rule.get("manual_ranges"):
        ranges = list(rule["manual_ranges"])
    ranges.extend(rule.get("extra_ranges", []))
    if not ranges:
        print(f"  ! {cve}: no usable ranges (add manual_ranges)", file=sys.stderr)
        return None
    out = {
        "cve": cve,
        "severity": rule["severity"],
        "title": rule["title"],
        "ranges": ranges,
        "remediation": rule["remediation"],
    }
    if rule.get("note"):
        out["note"] = rule["note"]
    print(f"  + {cve}: {len(ranges)} range(s)")
    return out


def update_db(refresh: bool) -> None:
    if DB_PATH.exists():
        db = json.loads(DB_PATH.read_text(encoding="utf-8"))
    else:
        db = {"schema_version": 1, "generated": "", "fingerprints": []}
    fingerprints = db.setdefault("fingerprints", [])
    by_product = {fp.get("product"): fp for fp in fingerprints}

    for fp in WATCHLIST:
        product = fp["product"]
        target = by_product.get(product)
        if target is None:
            target = {
                "product": product,
                "source": fp["source"],
                "regex": fp["regex"],
                "rules": [],
            }
            fingerprints.append(target)
            by_product[product] = target
        existing = {r["cve"]: r for r in target["rules"]}
        print(f"[{product}]")
        for rule in fp["rules"]:
            built = build_rule(rule, refresh)
            if built:
                existing[built["cve"]] = built
        target["rules"] = list(existing.values())

    db["schema_version"] = 1
    db["generated"] = time.strftime("%Y-%m-%d")
    DB_PATH.write_text(json.dumps(db, indent=2) + "\n", encoding="utf-8")
    rules = sum(len(f["rules"]) for f in fingerprints)
    print(f"\nwrote {DB_PATH} ({len(fingerprints)} fingerprints, {rules} rules)")


def check_db(refresh: bool) -> int:
    db = json.loads(DB_PATH.read_text(encoding="utf-8"))
    fingerprints = db.get("fingerprints", [])
    missing = []
    total = 0
    for fp in fingerprints:
        for rule in fp["rules"]:
            for part in re.findall(r"CVE-\d{4}-\d{4,7}", rule["cve"]):
                total += 1
                payload = fetch_cve(part, refresh=refresh)
                if not payload or not payload.get("vulnerabilities"):
                    missing.append(part)
                    print(f"  ! {part}: not found on NVD", file=sys.stderr)
                else:
                    print(f"  ok {part}")
    print(f"\nchecked {total} CVE IDs; missing: {len(missing)}")
    return 1 if missing else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="fetch NVD and rewrite the DB")
    parser.add_argument("--check", action="store_true", help="verify every CVE ID resolves on NVD")
    parser.add_argument("--refresh", action="store_true", help="ignore the local NVD cache")
    args = parser.parse_args()
    if not args.write and not args.check:
        parser.print_help()
        return 2
    if args.write:
        update_db(refresh=args.refresh)
    if args.check:
        return check_db(refresh=args.refresh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
