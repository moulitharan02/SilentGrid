#!/usr/bin/env bash
# =============================================================================
# start_live.sh — Run Zeek on a live interface and pipe it to Kafka
# Usage:
#   ./start_live.sh wlan0
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[→]${NC} $*"; }
error() { echo -e "${RED}[✘]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -eq 0 ]; then
    error "Please specify a network interface to capture on. Example: ./start_live.sh wlan0"
fi
IFACE=$1

info "Activating virtual environment..."
source venv/bin/activate

# Create a directory for live capture logs
ZEEK_DIR="$HOME/zeek-live"
mkdir -p "$ZEEK_DIR"
cd "$ZEEK_DIR"

info "Starting Zeek capture on interface $IFACE..."
warn "Note: This requires sudo to sniff traffic."

ZEEK_BIN=$(which zeek || echo "/usr/local/zeek/bin/zeek")

# Kill existing zeek if any
sudo pkill -f "$ZEEK_BIN" || true

# Run zeek in the background
sudo "$ZEEK_BIN" -i "$IFACE" &
ZEEK_PID=$!

info "Zeek is running (PID: $ZEEK_PID). Outputting to $ZEEK_DIR/conn.log"

cd "$SCRIPT_DIR"

# Ensure the log file exists so our Python tailer doesn't crash if there's no immediate traffic
touch "$ZEEK_DIR/conn.log"

# Run zeek_to_json to push live traffic into kafka
trap "sudo kill $ZEEK_PID 2>/dev/null || true; echo 'Stopped Zeek.'" EXIT
python zeek/zeek_to_json.py --log "$ZEEK_DIR/conn.log" --follow --kafka
