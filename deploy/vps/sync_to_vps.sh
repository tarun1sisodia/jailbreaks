#!/usr/bin/env bash
# Quick deployment helper to synchronize scripts and WebProbe to the VPS
# Usage: ./sync_to_vps.sh user@vps-host [ssh-port]

set -euo pipefail

TARGET="${1:-}"
PORT="${2:-22}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: ./sync_to_vps.sh <user@vps-host> [ssh-port]" >&2
    echo "Example: ./sync_to_vps.sh ubuntu@198.51.100.42 22" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "[*] Ensuring remote directories exist at /opt/mcp..."
ssh -p "$PORT" "$TARGET" "sudo mkdir -p /opt/mcp/{bin,repos,venvs,config,logs,run} && sudo chown -R \$USER:\$USER /opt/mcp"

echo "[*] Synchronizing configuration to /opt/mcp/config/..."
scp -P "$PORT" "${SCRIPT_DIR}/config/"* "${TARGET}:/opt/mcp/config/"

echo "[*] Synchronizing wrapper scripts to /opt/mcp/bin/..."
scp -P "$PORT" "${SCRIPT_DIR}/bin/"* "${TARGET}:/opt/mcp/bin/"

echo "[*] Synchronizing bootstrap script..."
scp -P "$PORT" "${SCRIPT_DIR}/bootstrap.sh" "${TARGET}:/opt/mcp/bootstrap.sh"

echo "[*] Synchronizing WebProbe repository to /opt/mcp/repos/webprobe/..."
if command -v rsync &>/dev/null; then
    rsync -avz --exclude '.git' --exclude '__pycache__' --exclude 'node_modules' --exclude '.venv' \
        -e "ssh -p ${PORT}" "${REPO_ROOT}/" "${TARGET}:/opt/mcp/repos/webprobe/"
else
    echo "  (rsync not found, using tar over ssh)"
    tar --exclude='.git' --exclude='__pycache__' --exclude='node_modules' --exclude='.venv' -czf - -C "${REPO_ROOT}" . | \
        ssh -p "$PORT" "$TARGET" "mkdir -p /opt/mcp/repos/webprobe && tar -xzf - -C /opt/mcp/repos/webprobe"
fi

echo "[*] Setting executable permissions on remote scripts..."
ssh -p "$PORT" "$TARGET" "chmod +x /opt/mcp/bin/* /opt/mcp/bootstrap.sh"

echo "---------------------------------------------------------"
echo "[+] Synchronization Complete!"
echo "To run the bootstrap setup on your VPS:"
echo "    ssh -p ${PORT} ${TARGET} 'bash /opt/mcp/bootstrap.sh'"
echo "---------------------------------------------------------"

