#!/usr/bin/env bash
# =============================================================================
# start.sh — nt-traffic-filter · Start the full pipeline
# Run this every time you want to start the system.
# Usage:
#   ./start.sh           # starts Kafka + main pipeline
#   ./start.sh --api     # starts Kafka + pipeline + REST API
#   ./start.sh --all     # starts everything including Docker app containers
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[→]${NC} $*"; }
error() { echo -e "${RED}[✘]${NC} $*"; exit 1; }
head()  { echo -e "\n${CYAN}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Docker Compose v2 (`docker compose`) vs legacy (`docker-compose`)
if docker compose version &>/dev/null; then
  DCOM=(docker compose)
elif command -v docker-compose &>/dev/null; then
  DCOM=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' is available. Install Docker Compose."
fi

START_API=false
for arg in "$@"; do
  [[ "$arg" == "--api" || "$arg" == "--all" ]] && START_API=true
done

echo ""
echo "============================================="
echo "   nt-traffic-filter · Starting Pipeline"
echo "============================================="

# ── 1. Activate venv ─────────────────────────────────────────────────────────
head "Step 1: Activating Python virtual environment..."
if [ ! -d "venv" ]; then
  error "Virtual environment not found. Please run ./setup.sh first."
fi
source venv/bin/activate
info "venv activated."

# ── 2. Ensure Docker daemon is running ────────────────────────────────────────
head "Step 2: Checking Docker daemon..."
if ! systemctl is-active --quiet docker 2>/dev/null; then
  warn "Docker is not running. Starting it..."
  systemctl start docker
  sleep 2
fi
info "Docker daemon is running."

# ── 3. Start Zookeeper ───────────────────────────────────────────────────────
head "Step 3: Starting Zookeeper..."
"${DCOM[@]}" -f docker/docker-compose.yml up zookeeper -d

warn "Waiting for Zookeeper to be healthy..."
for i in {1..30}; do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' nt-zookeeper 2>/dev/null || echo "missing")
  if [ "$STATUS" = "healthy" ]; then
    info "Zookeeper is healthy."
    break
  fi
  if [ "$i" -eq 30 ]; then
    error "Zookeeper did not become healthy in time. Run: sudo docker logs nt-zookeeper"
  fi
  sleep 2
done

# ── 4. Start Kafka ───────────────────────────────────────────────────────────
head "Step 4: Starting Kafka..."
"${DCOM[@]}" -f docker/docker-compose.yml up kafka -d

warn "Waiting for Kafka to be healthy (this can take up to 2 minutes)..."
for i in {1..60}; do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' nt-kafka 2>/dev/null || echo "missing")
  if [ "$STATUS" = "healthy" ]; then
    info "Kafka is healthy."
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo ""
    echo "Kafka logs:"
    docker logs nt-kafka 2>&1 | tail -20
    error "Kafka did not become healthy in time. See logs above."
  fi
  echo -ne "  Attempt $i/60 — status: $STATUS ...\r"
  sleep 5
done

# ── 5. Create Kafka topics ───────────────────────────────────────────────────
head "Step 5: Creating Kafka topics..."
docker exec nt-kafka kafka-topics \
  --create --if-not-exists \
  --bootstrap-server localhost:9092 \
  --topic raw-traffic \
  --partitions 3 \
  --replication-factor 1 2>/dev/null && info "Topic 'raw-traffic' ready." || warn "Topic may already exist."

docker exec nt-kafka kafka-topics \
  --create --if-not-exists \
  --bootstrap-server localhost:9092 \
  --topic traffic-alerts \
  --partitions 3 \
  --replication-factor 1 2>/dev/null && info "Topic 'traffic-alerts' ready." || warn "Topic may already exist."

# ── 6. Check models exist ────────────────────────────────────────────────────
head "Step 6: Checking ML models..."
MISSING_MODELS=false
for model in models/scaler.pkl models/anomaly.pkl models/classifier.pkl; do
  if [ ! -f "$model" ]; then
    warn "Missing model: $model"
    MISSING_MODELS=true
  fi
done
if $MISSING_MODELS; then
  echo ""
  echo -e "${YELLOW}⚠  ML models not found. The pipeline will run without ML detection.${NC}"
  echo -e "${YELLOW}   To train models, run:${NC}"
  echo -e "${YELLOW}     python training/train.py --data data/cicids.csv${NC}"
  echo ""
else
  info "All ML models found."
fi

# ── 7. Optionally start REST API ─────────────────────────────────────────────
if $START_API; then
  head "Step 7: Starting REST API server..."
  uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload &
  API_PID=$!
  echo "$API_PID" > .api.pid
  info "API started at http://localhost:8000/docs  (PID: $API_PID)"
fi

# ── 8. Start the pipeline ────────────────────────────────────────────────────
head "Step 8: Starting main pipeline..."
echo ""
echo "============================================="
echo -e "   ${GREEN}All systems go! Launching pipeline...${NC}"
echo "   Press Ctrl+C to stop."
echo "============================================="
echo ""

python -m src.main
