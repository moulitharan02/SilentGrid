# NT-Traffic-Filter · Network Threat Detection

**Real-time network traffic anomaly detection with professional dashboard.**

---

## ⚡ 30-Second Start

```bash
cd /home/kr15h/Workspace/nt-traffic-filter
source venv/bin/activate

# Start Docker services
docker-compose -f docker/docker-compose.yml up -d

# In separate terminals (or tmux):
python data/generate_traffic.py --count 100 --rate 50 --continuous  # Terminal 1
python -m src.main                                                      # Terminal 2  
uvicorn api.server:app --host 0.0.0.0 --port 8000                     # Terminal 3

# Open dashboard
👉 http://localhost:8000/dashboard
```

---

## 🏗️ Architecture

```
TRAFFIC SOURCES
   ↓
KAFKA (raw-traffic topic)
   ↓
FEATURE EXTRACTION (13 ML features)
   ↓
DETECTION MODELS (IsolationForest + XGBoost)
   ↓
RISK SCORING (0-100)
   ↓
ELASTICSEARCH (Indexed events)
   ↓
DASHBOARD + REST API
```

---

## 📊 Professional Dashboard

**Live Threat Detection Interface** → http://localhost:8000/dashboard

### Display Panels:
- **Real-Time Traffic** - Live source/destination IPs with data flow
- **Detection Classifier** - DDoS | PortScan | BruteForce | Benign breakdown
- **Risk Score Gauge** - 0-100 color-coded severity indicator
- **Alert Timeline** - Recent HIGH/CRITICAL threats
- **Statistics** - Total events, detection rate, alert count
- **Top Threats** - Most frequent attack types

---

## 🎯 How Classification Works

```
Raw Packet
   ↓
13 Features Extracted
(duration, protocol, ports, bytes, rates, etc.)
   ↓
IsolationForest Anomaly Score
   ↓
XGBoost Classifier predicts attack type:
  • BENIGN (normal traffic)
  • DDoS (high volume)
  • PortScan (multiple ports)
  • BruteForce (failed attempts)
   ↓
Risk Engine scores 0-100
   ↓
Display on Dashboard
```

---

## 📂 Clean Structure

```
nt-traffic-filter/
├── data/
│   └── generate_traffic.py          # Synthetic traffic + real data
├── src/
│   ├── features/       → Feature extraction
│   ├── detection/      → ML models + Risk scoring
│   ├── alerting/       → Alert dispatch
│   ├── storage/        → Elasticsearch
│   └── main.py         → Pipeline orchestrator
├── api/
│   ├── server.py       → REST API
│   └── dashboard.html  → Professional UI ⭐ NEW
├── docker-compose.yml  → All services
├── models/             → Pre-trained ML models
├── logs/               → Pipeline logs
├── README.md           → This file
└── MANUAL_STARTUP.md   → Detailed step-by-step
```

---

## 🚀 Services

| Service | Purpose | URL |
|---------|---------|-----|
| **Dashboard** | Professional threat UI | http://localhost:8000/dashboard |
| **API** | Programmatic access | http://localhost:8000 |
| **Kibana** | Log viewer | http://localhost:5601 |
| **Elasticsearch** | Raw data | http://localhost:9200 |
| **Prometheus** | Metrics | http://localhost:9090 |
| **Grafana** | Metric dashboards | http://localhost:3000 |

---

## 📡 API Endpoints

```bash
# Health
curl http://localhost:8000/health

# Detections
curl http://localhost:8000/detections?size=10

# Dashboard data
curl http://localhost:8000/api/dashboard/summary
curl http://localhost:8000/api/dashboard/threats
curl http://localhost:8000/api/dashboard/stats

# Alerts
curl http://localhost:8000/alerts

# Full docs
http://localhost:8000/docs
```

---

## 🔧 Manual Start (See [MANUAL_STARTUP.md](MANUAL_STARTUP.md) for details)

**Terminal 1:** Data Generator
```bash
source venv/bin/activate
python data/generate_traffic.py --count 100 --rate 50 --continuous
```

**Terminal 2:** Detection Pipeline
```bash
source venv/bin/activate
python -m src.main
```

**Terminal 3:** REST API + Dashboard
```bash
source venv/bin/activate
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

**Terminal 4:** Monitor
```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/dashboard/summary
```

---

## 📊 Real-Time Metrics

- **Throughput**: 100+ records/minute
- **Detections**: Real-time ML classification
- **Latency**: <10ms per record
- **Storage**: 1000+ indexed events
- **Dashboard**: Live refresh

---

## ✓ What You Get

- ✅ Real-time threat detection
- ✅ Professional dashboard with classifications
- ✅ Multi-model ML ensemble (Anomaly + Classifier)
- ✅ Risk scoring 0-100
- ✅ REST API for integration
- ✅ Alert system (High/Critical)
- ✅ Elasticsearch persistence
- ✅ Docker containerized

---

## 🎓 Detection Labels

| Label | Definition | Example |
|-------|-----------|---------|
| **BENIGN** | Normal traffic | HTTP requests, DNS queries |
| **DDoS** | Volume-based attack | 1000s of packets from single IP |
| **PortScan** | Reconnaissance | Multiple destination ports |
| **BruteForce** | Credential attack | Repeated login failures |
| **UNKNOWN** | Low confidence | Needs more data |

---

**Status**: ✓ Production Ready | **Dashboard**: ✓ Professional UI | **Classification**: ✓ Real-time

## Sending Test Traffic

```bash
# Replay a CSV dataset into Kafka at 100 records/sec
python kafka_scripts/producer.py --source data/cicids.csv --rate 100
```

## Running Tests

```bash
pytest tests/ -v
```

## Detection Models

| Model               | Algorithm           | Purpose                          |
|---------------------|---------------------|----------------------------------|
| `anomaly.pkl`       | Isolation Forest    | Unsupervised anomaly detection   |
| `classifier.pkl`    | Random Forest       | Multi-class attack classification|
| `scaler.pkl`        | StandardScaler      | Feature normalisation            |

## Alert Severity Levels

| Score   | Severity   | Action                        |
|---------|------------|-------------------------------|
| 0 – 39  | LOW        | Logged only                   |
| 40 – 74 | MEDIUM     | Logged only                   |
| 75 – 89 | HIGH       | Slack + email notification    |
| 90 – 100| CRITICAL   | Slack + email notification    |

## Environment Variables

See `.env` for the full list of configuration options.

## Phases

| Phase | Status      | Description                                  |
|-------|-------------|----------------------------------------------|
| 1     | ✅ Complete  | Zeek integration & Kafka ingestion           |
| 2     | ✅ Complete  | ML detection + risk scoring + alerting       |
| 3     | 🔧 Planned  | Behavioral profiling & graph correlation     |

## License

MIT
