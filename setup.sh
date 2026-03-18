#!/bin/bash
# VulnScanner — Kali Linux Setup Script
# Installs Node.js LTS, Docker, Docker Compose, MongoDB, and Git
# Run as root or with sudo: sudo bash setup.sh

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${CYAN}[VulnScanner Setup]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

log "=== VulnScanner Setup Script for Kali Linux ==="

# ── Update APT ──────────────────────────────────────────────
log "Updating package lists..."
apt-get update -qq

# ── Git ─────────────────────────────────────────────────────
log "Installing Git..."
apt-get install -y git curl wget gnupg ca-certificates lsb-release
success "Git installed"

# ── Node.js LTS (22.x) via NodeSource ───────────────────────
log "Installing Node.js LTS..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi
node --version && npm --version
success "Node.js $(node --version) installed"

# ── Docker ───────────────────────────────────────────────────
log "Installing Docker..."
if ! command -v docker &> /dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable docker
systemctl start docker
success "Docker $(docker --version) installed"

# ── Add current user to docker group ────────────────────────
CURRENT_USER=${SUDO_USER:-$USER}
if [ "$CURRENT_USER" != "root" ]; then
    usermod -aG docker "$CURRENT_USER"
    log "Added $CURRENT_USER to docker group (re-login required)"
fi

# ── Docker Compose standalone (fallback) ────────────────────
if ! docker compose version &> /dev/null 2>&1; then
    log "Installing Docker Compose standalone..."
    COMPOSE_VERSION="v2.24.5"
    curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    success "Docker Compose installed"
else
    success "Docker Compose already available"
fi

# ── MongoDB (optional — used inside Docker, but install for local dev) ──
log "Installing MongoDB client tools..."
if ! command -v mongosh &> /dev/null; then
    curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
        gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
        tee /etc/apt/sources.list.d/mongodb-org-7.0.list
    apt-get update -qq
    apt-get install -y mongodb-mongosh || log "mongosh install skipped (optional)"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  VulnScanner Setup Complete!               ${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo ""
log "To start the application:"
echo "  cd /path/to/Web-Application-VulnScanner"
echo "  cp .env.example .env"
echo "  docker compose up --build"
echo ""
log "Frontend: http://localhost:3000"
log "Backend API: http://localhost:5000"
echo ""
success "All done! 🛡️"
