"""SARIF 2.1.0 serialization. Ingested natively by GitHub/GitLab/SonarQube."""

import json
import time
from typing import Any, Dict, List

from webprobe.core import cvss, taxonomy


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"

LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "none": "note",
}


def _rule_id(finding) -> str:
    entry = taxonomy.lookup(finding.category)
    return entry["cwe"]


def _build_rules(findings: List[Any]) -> List[Dict]:
    seen = {}
    for f in findings:
        rid = _rule_id(f)
        if rid in seen:
            continue
        entry = taxonomy.lookup(f.category)
        seen[rid] = {
            "id": rid,
            "name": entry["title"].replace(" ", ""),
            "shortDescription": {"text": entry["title"]},
            "fullDescription": {
                "text": f"{entry['title']} ({entry['owasp']}). "
                        f"Compliance: {', '.join(taxonomy.compliance_notes(f.category))}"
            },
            "properties": {
                "tags": ["security", entry["owasp"], entry["cwe"]],
                "precision": "high",
                "security-severity": f"{cvss.base_v31(cvss.CWE_VECTORS.get(f.category, '')) or 5.0:.1f}",
            },
        }
    return list(seen.values())


def _result(finding) -> Dict:
    score, vector = cvss.score_for_category(finding.category)
    return {
        "ruleId": _rule_id(finding),
        "level": LEVEL_MAP.get(finding.severity.lower(), "warning"),
        "message": {
            "text": f"{finding.title} — {finding.evidence[:400]}"
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.url,
                },
            },
            "logicalLocations": [{
                "fullyQualifiedName": f"{finding.method or 'GET'} {finding.url}",
            }],
        }],
        "properties": {
            "severity": finding.severity,
            "phase": finding.phase,
            "param": finding.param,
            "payload": finding.payload,
            "remediation": finding.remediation,
            "cvss_score": score,
            "cvss_vector": vector,
        },
    }


def build_sarif(findings: List[Any], tool_name: str = "webprobe",
                tool_version: str = "3.0.0", target: str = "") -> str:
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/webprobe",
                    "rules": _build_rules(findings),
                }
            },
            "results": [_result(f) for f in findings],
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "properties": {"target": target},
            }],
        }],
    }
    return json.dumps(doc, indent=2)
