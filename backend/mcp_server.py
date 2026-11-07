#!/usr/bin/env python3
"""
WebProbe MCP Server
Exposes WebProbe security assessment and verification capabilities over stdio
for Model Context Protocol (MCP) clients and AI agents.
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("webprobe")

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

# Resolve Guardrail script location
VPS_GUARD = Path("/opt/mcp/bin/_guard.py")
LOCAL_GUARD = REPO_ROOT / "deploy" / "vps" / "bin" / "_guard.py"
GUARD_SCRIPT = str(VPS_GUARD if VPS_GUARD.exists() else LOCAL_GUARD)

# Resolve WebProbe executable
VPS_WEBPROBE = Path("/opt/mcp/bin/webprobe")
WEBPROBE_PY = BASE_DIR / "webprobe.py"
USE_DIRECT_PYTHON = not VPS_WEBPROBE.exists()


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="webprobe_scope_check",
            description="Verify if a domain or URL is permitted by the VPS scope guardrail.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname, domain, or full URL to check"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="webprobe_scan",
            description="Run full WebProbe security assessment against an in-scope target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target base URL (e.g. https://example.com)"
                    },
                    "profile": {
                        "type": "string",
                        "description": "Scan profile to execute",
                        "enum": [
                            "quick", "recon", "auth", "injection", "authz",
                            "business", "config", "owasp", "api", "full"
                        ],
                        "default": "quick"
                    },
                    "rate_limit": {
                        "type": "number",
                        "description": "Maximum requests per second (default: 3.0)",
                        "default": 3.0
                    },
                    "chain": {
                        "type": "boolean",
                        "description": "Chain related findings into compound vulnerabilities",
                        "default": True
                    },
                    "max_pages": {
                        "type": "integer",
                        "description": "Maximum pages to crawl",
                        "default": 30
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="webprobe_exploit",
            description="Run authorized exploit verification chains (e.g. React2Shell, Supabase RLS, Razorpay logic).",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target base URL"
                    },
                    "exploit_rce": {
                        "type": "boolean",
                        "description": "Prove RCE via React2Shell (runs bounded benign command)",
                        "default": False
                    },
                    "webhook_url": {
                        "type": "string",
                        "description": "Explicit payment webhook endpoint URL"
                    }
                },
                "required": ["url"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    # 1. Scope check tool
    if name == "webprobe_scope_check":
        target = arguments.get("target", "")
        r = subprocess.run([sys.executable, GUARD_SCRIPT, "--check", target], capture_output=True, text=True)
        in_scope = (r.returncode == 0)
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "target": target,
                    "in_scope": in_scope,
                    "message": r.stdout.strip() if in_scope else r.stderr.strip()
                }, indent=2)
            )
        ]

    # For scan or exploit, target URL is mandatory
    target_url = arguments.get("url", "")
    if not target_url:
        return [TextContent(type="text", text=json.dumps({"error": "Missing required argument 'url'"}))]

    # 2. Strict Guardrail Verification
    guard = subprocess.run([sys.executable, GUARD_SCRIPT, "--check", target_url], capture_output=True, text=True)
    if guard.returncode != 0:
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "error": "REFUSED: Target is out of scope",
                    "details": guard.stderr.strip()
                }, indent=2)
            )
        ]

    # Prepare temp report file for structured JSON output
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{BASE_DIR}:{env.get('PYTHONPATH', '')}"

    try:
        # Build command invocation
        if USE_DIRECT_PYTHON:
            cmd = [sys.executable, str(WEBPROBE_PY), target_url]
        else:
            cmd = [str(VPS_WEBPROBE), target_url]

        if name == "webprobe_scan":
            cmd.extend([
                "--profile", arguments.get("profile", "quick"),
                "--rate-limit", str(arguments.get("rate_limit", 3.0)),
                "--max-pages", str(arguments.get("max_pages", 30)),
                "--json", "-o", report_path
            ])
            if not arguments.get("chain", True):
                cmd.append("--no-chain")

        elif name == "webprobe_exploit":
            cmd.extend([
                "--profile", "exploit",
                "--exploit",
                "--json", "-o", report_path
            ])
            if arguments.get("exploit_rce"):
                cmd.append("--exploit-rce")
            if arguments.get("webhook_url"):
                cmd.extend(["--webhook-url", arguments["webhook_url"]])
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        # Execute scan
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)

        findings = []
        if Path(report_path).exists() and Path(report_path).stat().st_size > 0:
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    findings = json.load(f)
            except Exception as e:
                findings = [{"error": f"Failed to parse report JSON: {e}"}]

        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "exit_code": proc.returncode,
                    "findings_count": len(findings) if isinstance(findings, list) else 0,
                    "findings": findings,
                    "stderr": proc.stderr[-2000:] if proc.stderr else ""
                }, indent=2)
            )
        ]

    except subprocess.TimeoutExpired:
        return [TextContent(type="text", text=json.dumps({"error": "Assessment timed out after 900 seconds"}))]
    except Exception as exc:
        return [TextContent(type="text", text=json.dumps({"error": f"Execution failed: {exc}"}))]
    finally:
        Path(report_path).unlink(missing_ok=True)


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())

