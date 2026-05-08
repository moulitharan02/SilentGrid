# nt-traffic-filter · Project Overview & Workflow

## What This Project Does
A real-time network traffic anomaly detection and threat alerting pipeline. It acts as an enterprise-ready SIEM + IDS hybrid system — moving beyond simple packet inspection to tracking multi-stage attack chains, lateral movement, and C2 node detection.

---

## High-Level Architecture

```
[Zeek log / CSV dataset]
         ↓
[Kafka (raw-traffic topic)]
         ↓
[nt-traffic-filter Main Pipeline]
   ├─ Feature Engineering       (extract + normalize)
   ├─ IsolationForest           (anomaly detection)
   ├─ RandomForestClassifier    (attack classification)
   ├─ Risk Engine               (0–100 score)
   ├─ Graph Engine / NetworkX   (C2 + lateral movement)
   ├─ Correlation Engine        (attack chain detection)
   ├─ Threat Intel Engine       (IP reputation lookup)
   └─ Alert Manager             (Slack / Email / logs)
         ↓
[FastAPI REST Server]           (http://localhost:8000)
```

---

## Detailed Workflow

1. **Ingestion** — Zeek or a CSV producer publishes JSON records to Kafka topic `raw-traffic`
2. **Feature Engineering** — `FeatureEngine` extracts 13 numerical features (duration, bytes, packet rates, etc.)
3. **ML Detection**
   - `StandardScaler` normalizes features
   - `IsolationForest` flags unsupervised anomalies
   - `RandomForestClassifier` labels the attack type (BENIGN, DDoS, PortScan, etc.)
4. **Risk Scoring** — A 0–100 score is computed from model confidence and anomaly severity
5. **Intelligence Layer**
   - `GraphEngine` (NetworkX) tracks connections and identifies C2 nodes
   - `CorrelationEngine` matches behaviors across time into attack chains
   - `IntelEngine` queries AbuseIPDB for known malicious IPs
6. **Alerting** — HIGH (75–89) and CRITICAL (90–100) events fire Slack + Email alerts
7. **REST API** — `/health`, `/stats`, `/alerts` expose system state for dashboards

---

## Alert Severity Levels

| Score    | Severity | Action                      |
|----------|----------|-----------------------------|
| 0 – 39   | LOW      | Logged only                 |
| 40 – 74  | MEDIUM   | Logged only                 |
| 75 – 89  | HIGH     | Slack + Email notification  |
| 90 – 100 | CRITICAL | Slack + Email notification  |

---

## Project File Structure

```
nt-traffic-filter/
├── setup.sh               ← ONE-TIME setup for new machines
├── start.sh               ← Start full pipeline (use every time)
├── stop.sh                ← Stop all services cleanly
├── requirements.txt       ← Python dependencies
├── .env                   ← Configuration (Kafka, SMTP, Slack)
├── data/                  ← CICIDS-2017 CSV dataset (you provide)
├── models/                ← Trained .pkl model files (auto-generated)
├── logs/                  ← Runtime + alert logs
├── zeek/                  ← Zeek conn.log → JSON/Kafka converter
├── kafka/                 ← Kafka topic helper scripts
├── docker/                ← docker-compose.yml (Zookeeper + Kafka)
├── src/
│   ├── config/            ← Env-driven central config
│   ├── consumer/          ← Kafka consumer
│   ├── features/          ← Feature extraction engine
│   ├── detection/         ← Anomaly + classifier + risk engine
│   ├── behavior/          ← Per-host behavioral profiling
│   ├── correlation/       ← Graph-based attack chain correlation
│   ├── threat_intel/      ← AbuseIPDB threat intelligence
│   ├── alerting/          ← Slack / Email alert manager
│   └── main.py            ← Pipeline entry point
├── training/
│   └── train.py           ← Offline ML model trainer
├── api/
│   └── server.py          ← FastAPI REST server
└── tests/                 ← pytest integration tests
```

---

## How to Run (Quick Reference)

### First time on a new machine
```bash
chmod +x setup.sh start.sh stop.sh
./setup.sh
```

### Train ML models (requires CICIDS-2017 dataset in data/)
```bash
python training/train.py --data data/cicids.csv
```

### Start the pipeline every time
```bash
./start.sh           # Kafka + main pipeline
./start.sh --api     # + REST API at http://localhost:8000/docs
```

### Stop everything
```bash
./stop.sh
```

### Send test traffic through the pipeline
```bash
python kafka/producer.py --source data/cicids.csv --rate 100
```

### Stream from a real Zeek log
```bash
python zeek/zeek_to_json.py \
  --log /var/log/zeek/current/conn.log \
  --follow --kafka --topic raw-traffic --bootstrap localhost:9092
```

### Run tests
```bash
pytest tests/ -v
```

---

## Configuration (.env)

| Variable                  | Default            | Description                        |
|---------------------------|--------------------|------------------------------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092`   | Kafka broker address               |
| `KAFKA_TOPIC_RAW`         | `raw-traffic`      | Inbound traffic topic              |
| `KAFKA_TOPIC_ALERTS`      | `traffic-alerts`   | Outbound alert topic               |
| `ANOMALY_THRESHOLD`       | `-0.5`             | IsolationForest cutoff             |
| `RISK_HIGH_THRESHOLD`     | `75`               | Score above which alerts fire      |
| `SLACK_WEBHOOK_URL`       | _(empty)_          | Slack webhook for HIGH/CRITICAL    |
| `EMAIL_SENDER`            | _(empty)_          | Gmail sender address               |
| `EMAIL_RECIPIENTS`        | _(empty)_          | Comma-separated recipients         |

---

## ML Models

| File             | Algorithm           | Purpose                            |
|------------------|---------------------|------------------------------------|
| `scaler.pkl`     | StandardScaler      | Feature normalization              |
| `anomaly.pkl`    | IsolationForest     | Unsupervised anomaly detection     |
| `classifier.pkl` | RandomForestClassifier | Multi-class attack labeling     |

---

## REST API Endpoints

| Endpoint  | Method | Description                               |
|-----------|--------|-------------------------------------------|
| `/`       | GET    | Service info                              |
| `/health` | GET    | Liveness check + model availability       |
| `/stats`  | GET    | Runtime config + alert count              |
| `/alerts` | GET    | Last N alert log entries (default: 50)    |
| `/docs`   | GET    | Interactive Swagger UI                    |

---

## Known Fixes Applied

| Issue | Fix |
|-------|-----|
| `kafka-python` broken on Python 3.12/3.13 (`six` module missing) | Replaced with `kafka-python-ng` in `requirements.txt` |
| `docker compose` failing on Kali Linux | Use `docker-compose` (with hyphen) and `docker.io` package |
| `version` field warning in docker-compose | Removed obsolete `version: "3.9"` from `docker-compose.yml` |
| `kafka-topics.sh` not found locally | Topics now created via `docker exec nt-kafka kafka-topics ...` |
