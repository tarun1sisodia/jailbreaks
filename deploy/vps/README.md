# VPS Security Assessment Hub & MCP Bridge

This directory contains the production-ready deployment scripts, guardrail policies, CLI wrappers, and MCP server configuration for running **WebProbe** alongside wrapped ecosystem scanners (**KageSec**, **TridentChain**, **Argus**, **OpenOSINT**, and **SAST MCP**) on an isolated VPS.

---

## Architecture Overview

```
AI Agent (Cloud / Local IDE)
          │
          │ SSH stdio MCP Transport (Zero open ports, authenticated via SSH key)
          ▼
VPS Host (/opt/mcp/)
   │
   ├── [Guardrail] /opt/mcp/bin/_guard.py ← Reads /opt/mcp/config/scope.toml
   │
   ├── Layer 1: Custom Engine (WebProbe)
   │     └── /opt/mcp/repos/webprobe/backend/mcp_server.py
   │
   └── Layer 2: Wrapped Breadth Ecosystem (Isolated per-tool venvs)
         ├── KageSec      (/opt/mcp/venvs/kagesec/)      → 7,400 CVE templates & Playwright crawler
         ├── TridentChain (/opt/mcp/venvs/tridentchain/) → Supply-chain SCA vulnerability scans
         ├── Argus        (/opt/mcp/venvs/argus/)        → Unified SAST/DAST scanner orchestration
         ├── OpenOSINT    (/opt/mcp/venvs/openosint/)    → Passive OSINT & reconnaissance
         └── SAST Server  (Docker container)            → Static application security testing
```

---

## Directory Layout on VPS

```
/opt/mcp/
├── bin/                    # All wrappers execute _guard.py before running
│   ├── _guard.py           # Scope validator (exits 2 on unauthorized targets)
│   ├── webprobe            # WebProbe launcher setting PYTHONPATH
│   ├── kagesec-scan        # KageSec runner
│   ├── tridentchain-scan   # SCA manifest scanner
│   ├── openosint-query     # Passive OSINT runner
│   └── argus-scan          # Argus runner
├── repos/
│   └── webprobe/           # Your repository clone
├── venvs/                  # Fully isolated virtualenvs per tool (no dependency drift)
│   ├── webprobe/           # Contains mcp SDK
│   ├── kagesec/
│   ├── tridentchain/
│   ├── argus/
│   └── openosint/
├── config/
│   └── scope.toml          # Target allowlist & strict deny rules
└── logs/
```

---

## Deployment Steps

### Step 1: Synchronize to VPS

From your local terminal, run the sync helper:

```bash
chmod +x deploy/vps/sync_to_vps.sh
./deploy/vps/sync_to_vps.sh ubuntu@<your-vps-ip>
```

Or manually copy the files:

```bash
ssh user@<vps> "sudo mkdir -p /opt/mcp/{bin,repos,venvs,config,logs,run} && sudo chown -R \$USER:\$USER /opt/mcp"
scp -r deploy/vps/bin/* user@<vps>:/opt/mcp/bin/
scp -r deploy/vps/config/* user@<vps>:/opt/mcp/config/
scp deploy/vps/bootstrap.sh user@<vps>:/opt/mcp/bootstrap.sh
rsync -avz --exclude '.git' --exclude '__pycache__' --exclude '.venv' ./ user@<vps>:/opt/mcp/repos/webprobe/
```

### Step 2: Run Bootstrap on the VPS

SSH into your VPS and run the bootstrap script:

```bash
ssh user@<your-vps-ip>
cd /opt/mcp
chmod +x bin/* bootstrap.sh
./bootstrap.sh
```

### Step 3: Verify the Scope Guardrail

Test that authorized targets pass and foreign targets fail:

```bash
# Must PASS (Exit code 0):
/opt/mcp/bin/_guard.py --check "https://agraskbagheltourandtravels.com"

# Must FAIL (Exit code 2):
/opt/mcp/bin/_guard.py --check "https://target.gov"
```

---

## Cloud Agent Configuration

### 1. SSH Connection Multiplexing (Low Latency)

In `~/.ssh/config` on your local/cloud agent machine, add:

```ssh
Host vps.example.com
    HostName <your-vps-ip>
    User ubuntu
    IdentityFile ~/.ssh/id_rsa
    ControlMaster auto
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlPersist 15m
    ServerAliveInterval 30
```

*This keeps the SSH socket alive, dropping subsequent MCP execution latency from ~350ms to <15ms.*

### 2. Agent MCP Config (`claude_desktop_config.json` or Agent Settings)

```json
{
  "mcpServers": {
    "webprobe": {
      "command": "ssh",
      "args": [
        "vps.example.com",
        "/opt/mcp/venvs/webprobe/bin/python3",
        "/opt/mcp/repos/webprobe/backend/mcp_server.py"
      ]
    },
    "kagesec": {
      "command": "ssh",
      "args": [
        "vps.example.com",
        "/opt/mcp/venvs/kagesec/bin/kagesec",
        "mcp",
        "--stdio"
      ]
    },
    "openosint": {
      "command": "ssh",
      "args": [
        "vps.example.com",
        "/opt/mcp/venvs/openosint/bin/openosint",
        "mcp"
      ]
    },
    "argus": {
      "command": "ssh",
      "args": [
        "vps.example.com",
        "/opt/mcp/venvs/argus/bin/argus",
        "mcp",
        "--stdio"
      ]
    }
  }
}
```

