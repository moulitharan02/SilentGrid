#!/usr/bin/env bash
# =============================================================================
# stop.sh — nt-traffic-filter · Gracefully stop all services
# Usage:
#   ./stop.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[→]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if docker compose version &>/dev/null; then
  DCOM=(docker compose)
elif command -v docker-compose &>/dev/null; then
  DCOM=(docker-compose)
else
  DCOM=()
fi

echo ""
echo "============================================="
echo "   nt-traffic-filter · Stopping Services"
echo "============================================="
echo ""

# ── Stop REST API if running ──────────────────────────────────────────────────
if [ -f ".api.pid" ]; then
  API_PID=$(cat .api.pid)
  if kill -0 "$API_PID" 2>/dev/null; then
    warn "Stopping REST API (PID: $API_PID)..."
    kill "$API_PID" 2>/dev/null || true
    info "REST API stopped."
  fi
  rm -f .api.pid
fi

# ── Stop Kafka and Zookeeper ──────────────────────────────────────────────────
warn "Stopping Kafka and Zookeeper containers..."
if [ "${#DCOM[@]}" -gt 0 ]; then
  sudo "${DCOM[@]}" -f docker/docker-compose.yml stop kafka zookeeper 2>/dev/null || true
fi
info "Kafka and Zookeeper stopped."

echo ""
info "All services stopped cleanly."
echo ""
echo "To remove containers entirely:  sudo docker compose -f docker/docker-compose.yml down"
echo "To start again:                 ./start.sh"
echo ""
