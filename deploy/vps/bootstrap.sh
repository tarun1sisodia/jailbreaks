#!/usr/bin/env bash
# WebProbe & Ecosystem VPS Bootstrap Script
# Run once on a fresh Ubuntu 22.04 / 24.04 VPS as a sudo-capable user.
set -euo pipefail

MCP_ROOT="/opt/mcp"
echo "[*] Initializing MCP directory layout at ${MCP_ROOT}..."
sudo mkdir -p "${MCP_ROOT}"/{bin,repos,venvs,config,logs,run}
sudo chown -R "${USER}:${USER}" "${MCP_ROOT}"
cd "${MCP_ROOT}"

echo "[*] Installing core system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq git curl jq python3-venv python3-pip \
    build-essential libssl-dev ca-certificates

# Install uv (blazing fast Python venv & package installer)
if ! command -v uv &>/dev/null; then
    echo "[*] Installing Astral uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

# Install Docker for SAST and containerized tools
if ! command -v docker &>/dev/null; then
    echo "[*] Installing Docker Engine..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "${USER}"
    echo "[!] Added ${USER} to docker group. (Note: group membership activates on new shell session)"
fi

echo "[*] Creating isolated virtual environments..."

# 1. WebProbe MCP Environment
echo "  -> Setting up venvs/webprobe..."
uv venv venvs/webprobe --python 3.12
. venvs/webprobe/bin/activate
uv pip install "mcp>=1.0.0"
deactivate

# 2. KageSec DAST & Templates
echo "  -> Setting up venvs/kagesec..."
uv venv venvs/kagesec --python 3.12
. venvs/kagesec/bin/activate
uv pip install kagesec playwright
# Install headless Chromium for browser crawler
playwright install --with-deps chromium
deactivate

# 3. TridentChain SCA Scanner
echo "  -> Setting up venvs/tridentchain..."
uv venv venvs/tridentchain --python 3.12
. venvs/tridentchain/bin/activate
uv pip install tridentchain-security
deactivate

# 4. Argus Security Platform
echo "  -> Setting up venvs/argus..."
uv venv venvs/argus --python 3.12
. venvs/argus/bin/activate
uv pip install argus-security
deactivate

# 5. OpenOSINT Passive Reconnaissance
echo "  -> Setting up venvs/openosint..."
uv venv venvs/openosint --python 3.12
. venvs/openosint/bin/activate
uv pip install openosint
deactivate

# 6. SAST MCP Server (Docker image)
echo "[*] Pulling sast-mcp-server image..."
sudo docker pull ghcr.io/skyrxin/sast-mcp-server:full || true

echo "---------------------------------------------------------"
echo "[+] VPS Bootstrap Complete!"
echo "Next steps:"
echo " 1. Ensure your webprobe repo is cloned to: ${MCP_ROOT}/repos/webprobe"
echo " 2. Ensure ${MCP_ROOT}/config/scope.toml contains your target domains"
echo " 3. Verify tool versions:"
echo "    - ${MCP_ROOT}/venvs/kagesec/bin/kagesec --version"
echo "    - ${MCP_ROOT}/venvs/tridentchain/bin/tridentchain --version"
echo "    - ${MCP_ROOT}/venvs/argus/bin/argus --version"
echo "    - ${MCP_ROOT}/venvs/openosint/bin/openosint --version"
echo "---------------------------------------------------------"

