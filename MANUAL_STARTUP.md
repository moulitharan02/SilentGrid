# Manual Startup Guide · NT-Traffic-Filter

Complete step-by-step instructions to manually start all components.

---

## Prerequisites

```bash
# Verify Python venv is active
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Verify Docker is running
docker ps
```

---

## Step 1: Start Docker Services

Start the core infrastructure services (Kafka, Elasticsearch, Redis, Zookeeper).

### Option A: Start All Docker Services
```bash
cd /home/kr15h/Workspace/nt-traffic-filter

# Start all services in background
docker-compose -f docker/docker-compose.yml up -d zookeeper kafka elasticsearch redis prometheus grafana kibana

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 30

# Verify all are running
docker-compose -f docker/docker-compose.yml ps
```

### Option B: Start Services Individually
```bash
# Terminal 1: Zookeeper
docker-compose -f docker/docker-compose.yml up zookeeper

# Terminal 2: Kafka (depends on Zookeeper)
docker-compose -f docker/docker-compose.yml up kafka

# Terminal 3: Elasticsearch
docker-compose -f docker/docker-compose.yml up elasticsearch

# Terminal 4: Redis
docker-compose -f docker/docker-compose.yml up redis

# Terminal 5: Prometheus
docker-compose -f docker/docker-compose.yml up prometheus

# Terminal 6: Grafana
docker-compose -f docker/docker-compose.yml up grafana

# Terminal 7: Kibana
docker-compose -f docker/docker-compose.yml up kibana
```

---

## Step 2: Create Kafka Topics

In a new terminal:

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Create raw-traffic topic
docker exec nt-kafka kafka-topics \
  --create --if-not-exists \
  --bootstrap-server localhost:9092 \
  --topic raw-traffic \
  --partitions 3 \
  --replication-factor 1

# Create alerts topic
docker exec nt-kafka kafka-topics \
  --create --if-not-exists \
  --bootstrap-server localhost:9092 \
  --topic traffic-alerts \
  --partitions 3 \
  --replication-factor 1

# Verify topics created
docker exec nt-kafka kafka-topics --list --bootstrap-server localhost:9092
```

---

## Step 3: Start Synthetic Traffic Generator

**Terminal A:** (Continuous data generation)

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Start continuous traffic generation (100 records/batch, 50 records/sec)
python data/generate_traffic.py --count 100 --rate 50 --continuous

# Output should show:
# Generating traffic continuously (Ctrl+C to stop)...
# ✓ Generated 100 synthetic network traffic records to Kafka
# Waiting 30 seconds before next batch...
```

---

## Step 4: Start Main Detection Pipeline

**Terminal B:** (Detection pipeline)

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Start the main pipeline
python -m src.main

# Output should show banner with:
# [✔] Starting Pipeline
# [✔] VulnXploit Core (Phase 3)
# [✔] Kafka Bootstrap: localhost:9092
# [✔] Initialising pipeline...
# [✔] Processed record — label=BENIGN  risk= XX  severity=LOW
```

---

## Step 5: Start REST API Server

**Terminal C:** (REST API)

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Start FastAPI server
uvicorn api.server:app --host 0.0.0.0 --port 8000

# Output should show:
# INFO:     Uvicorn running on http://0.0.0.0:8000
# INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

## Step 6: Verify Everything is Running

**Terminal D:** (Verification)

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Check API health
curl http://localhost:8000/health | python -m json.tool

# Expected output:
# {
#     "status": "ok",
#     "models": {
#         "scaler": true,
#         "anomaly": true,
#         "classifier": true
#     },
#     "elasticsearch": true
# }

# Check detected records in Elasticsearch
python << 'EOF'
from elasticsearch import Elasticsearch
es = Elasticsearch(["http://localhost:9200"])
result = es.search(index="nt-detections-2026.05.08", size=1)
total = result['hits']['total']['value']
print(f"Documents indexed: {total}")
EOF

# Check Kafka messages flowing
docker exec nt-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic raw-traffic \
  --max-messages 3 \
  --from-beginning
```

---

## Terminal Layout Example

```
┌─────────────────────────────────────────────────────────┐
│ Terminal A: Traffic Generator       Terminal B: Pipeline │
│ $ python data/generate...           $ python -m src.main │
│ ✓ Generated 100 records             ✓ Processing...      │
├─────────────────────────────────────────────────────────┤
│ Terminal C: REST API                Terminal D: Monitor  │
│ $ uvicorn api.server:app            $ curl /health      │
│ INFO: Running on :8000              ✓ Status: OK        │
└─────────────────────────────────────────────────────────┘
```

---

## All Dashboard URLs

Once everything is running, access:

| Service | URL | Purpose |
|---------|-----|---------|
| REST API | http://localhost:8000 | Primary control center |
| Kibana | http://localhost:5601 | Log viewer & search |
| Elasticsearch | http://localhost:9200 | Raw data |
| Prometheus | http://localhost:9090 | Metrics scraper |
| Grafana | http://localhost:3000 | Metric dashboards |

---

## Quick Commands Reference

### Check Status
```bash
# Docker services
docker-compose -f docker/docker-compose.yml ps

# Kafka topics
docker exec nt-kafka kafka-topics --list --bootstrap-server localhost:9092

# API health
curl -s http://localhost:8000/health | python -m json.tool

# Elasticsearch docs
curl -s http://localhost:9200/nt-detections-2026.05.08/_search?size=1 | python -m json.tool
```

### Stop Everything
```bash
# Kill Python processes
pkill -f "python.*generate_traffic\|python -m src.main\|uvicorn"

# Stop Docker services
docker-compose -f docker/docker-compose.yml down

# Or specific service
docker-compose -f docker/docker-compose.yml stop <service-name>
```

### View Logs
```bash
tail -f logs/pipeline.log        # Pipeline logs
tail -f logs/generator.log       # Generator logs
tail -f logs/api.log             # API logs
tail -f logs/alerts.log          # Alert logs
```

### Monitor Data Flow
```bash
# Watch Elasticsearch document count grow
watch -n 5 'curl -s http://localhost:9200/nt-detections-2026.05.08/_search | python -c "import sys,json; print(json.load(sys.stdin)[\"hits\"][\"total\"][\"value\"])"'

# Watch pipeline logs
watch -n 2 'tail -5 logs/pipeline.log'

# Check thread count (system load)
ps aux | grep python | grep -E "generate_traffic|src.main|uvicorn" | wc -l
```

---

## Troubleshooting

### Services won't connect
```bash
# Check Docker daemon
docker ps

# Check ports are free
netstat -tlnp | grep -E "9092|9200|5601|3000|8000"

# Restart Docker
sudo systemctl restart docker
```

### Kafka connection refused
```bash
# Verify Kafka container
docker ps | grep kafka

# Check Kafka logs
docker logs nt-kafka | tail -50

# Recreate topics
docker exec nt-kafka kafka-topics --delete --topic raw-traffic --bootstrap-server localhost:9092
docker exec nt-kafka kafka-topics --create --topic raw-traffic --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1
```

### No data in Elasticsearch
```bash
# Check if documents are being written
curl http://localhost:9200/nt-detections-2026.05.08/_search

# Check pipeline logs for errors
grep -i error logs/pipeline.log

# Verify data in Kafka
docker exec nt-kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic raw-traffic --max-messages 1
```

### High CPU usage
```bash
# Check what's consuming CPU
top

# Reduce traffic generation rate
# Edit: python data/generate_traffic.py --count 50 --rate 10 --continuous
```

---

## Success Indicators

✓ **All running successfully when you see:**

1. **Generator Terminal**: "Generated X synthetic network traffic records" every 30 seconds
2. **Pipeline Terminal**: "Processed record" messages flowing continuously
3. **API Terminal**: "Uvicorn running on http://0.0.0.0:8000"
4. **Monitor Terminal**:
   - `curl http://localhost:8000/health` returns `"status": "ok"`
   - Elasticsearch document count > 100 and growing

---

## Production Tips

```bash
# Run in background (detached)
nohup python data/generate_traffic.py --count 100 --rate 50 --continuous > logs/generator.log 2>&1 &
nohup python -m src.main > logs/pipeline.log 2>&1 &
nohup uvicorn api.server:app --host 0.0.0.0 --port 8000 > logs/api.log 2>&1 &

# Monitor with tmux/screen for better persistence
tmux new-session -d -s generator "python data/generate_traffic.py --count 100 --rate 50 --continuous"
tmux new-session -d -s pipeline "python -m src.main"
tmux new-session -d -s api "uvicorn api.server:app --host 0.0.0.0 --port 8000"

# Create systemd service for auto-start (advanced)
# See: https://docs.python-guide.org/writing/logging/
```

---

**Ready to start? Begin with Step 1 and open 4-7 terminals!**
