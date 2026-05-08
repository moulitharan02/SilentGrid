#!/usr/bin/env bash
# =============================================================================
# setup.sh — nt-traffic-filter · One-time system setup
# Run this ONCE on a new machine to install all system dependencies.
# Supports: Kali Linux / Debian / Ubuntu
# Usage:
#   chmod +x setup.sh && ./setup.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✘]${NC} $*"; exit 1; }

# ── 0. Must be run from project root ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "============================================="
echo "   nt-traffic-filter · System Setup"
echo "============================================="
echo ""

# ── 1. Install Docker Engine (docker.io) ─────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  info "Docker daemon already installed and running."
else
  warn "Installing Docker engine (docker.io) ..."
  sudo apt-get update -qq
  sudo apt-get install -y docker.io docker-compose
  info "Docker installed."
fi

# ── 2. Start and enable Docker daemon ────────────────────────────────────────
if ! sudo systemctl is-active --quiet docker; then
  warn "Starting Docker daemon ..."
  sudo systemctl start docker
  sudo systemctl enable docker
  info "Docker daemon started."
else
  info "Docker daemon is already running."
fi

# ── 3. Add current user to docker group (no sudo needed in future) ───────────
if ! groups "$USER" | grep -q docker; then
  warn "Adding $USER to docker group (you may need to log out and back in) ..."
  sudo usermod -aG docker "$USER"
  info "Added to docker group."
else
  info "User $USER is already in the docker group."
fi

# ── 4. Set up Python virtual environment ─────────────────────────────────────
if [ ! -d "venv" ]; then
  warn "Creating Python virtual environment ..."
  python3 -m venv venv
  info "Virtual environment created."
else
  info "Virtual environment already exists."
fi

# ── 5. Install Python dependencies ───────────────────────────────────────────
warn "Installing Python dependencies ..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
info "Python dependencies installed."

# ── 6. Create required directories ───────────────────────────────────────────
mkdir -p logs models data
info "Runtime directories ensured: logs/, models/, data/"

# ── 7. Create .env if missing ─────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  warn "No .env file found — creating one from defaults ..."
  cat > .env <<'EOF'
# ── Kafka ─────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC_RAW=raw-traffic
KAFKA_TOPIC_ALERTS=traffic-alerts
KAFKA_GROUP_ID=nt-filter-group
KAFKA_AUTO_OFFSET_RESET=earliest

# ── Models ────────────────────────────────────────────
MODEL_DIR=models

# ── Logging ───────────────────────────────────────────
LOG_DIR=logs
LOG_LEVEL=INFO

# ── Detection thresholds ──────────────────────────────
ANOMALY_THRESHOLD=-0.5
RISK_HIGH_THRESHOLD=75
RISK_MED_THRESHOLD=40

# ── Alerting (optional) ───────────────────────────────
SLACK_WEBHOOK_URL=
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_SENDER=
EMAIL_PASSWORD=
EMAIL_RECIPIENTS=
EOF
  info ".env file created with defaults."
else
  info ".env file already exists."
fi

echo ""
echo "============================================="
echo -e "   ${GREEN}Setup complete!${NC}"
echo "============================================="
echo ""
echo "Next steps:"
echo "  1. Activate venv:    source venv/bin/activate"
echo "  2. Train models:     python training/train.py --data data/cicids.csv"
echo "  3. Start pipeline:   ./start.sh"
echo ""
warn "NOTE: If this is your first time being added to the docker group,"
warn "you may need to run: newgrp docker   (or log out and back in)"
echo ""
