"""
Central configuration module for nt-traffic-filter.
All settings are loaded from environment variables / .env file.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Kafka ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC_RAW: str         = os.getenv("KAFKA_TOPIC_RAW", "raw-traffic")
KAFKA_TOPIC_ALERTS: str      = os.getenv("KAFKA_TOPIC_ALERTS", "traffic-alerts")
KAFKA_GROUP_ID: str          = os.getenv("KAFKA_GROUP_ID", "nt-filter-group")
KAFKA_AUTO_OFFSET_RESET: str = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")

# ─── Models ───────────────────────────────────────────────────────────────────
MODEL_DIR: str          = os.getenv("MODEL_DIR", "models")
ANOMALY_MODEL_PATH: str = os.path.join(MODEL_DIR, "anomaly.pkl")
CLASSIFIER_MODEL_PATH: str = os.path.join(MODEL_DIR, "classifier.pkl")
XGBOOST_MODEL_PATH: str = os.path.join(MODEL_DIR, "xgboost_model.onnx")
RF_ONNX_PATH: str       = os.path.join(MODEL_DIR, "rf_model.onnx")
SCALER_PATH: str        = os.path.join(MODEL_DIR, "scaler.pkl")

# ─── Storage / Cache ──────────────────────────────────────────────────────────
REDIS_HOST: str         = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int         = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB: int           = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD: str     = os.getenv("REDIS_PASSWORD", "")

# ─── Elasticsearch ────────────────────────────────────────────────────────────
ELASTICSEARCH_HOST: str          = os.getenv("ELASTICSEARCH_HOST", "localhost:9200")
ELASTICSEARCH_INDEX_PREFIX: str  = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "nt-detections")
ELASTICSEARCH_TIMEOUT: int       = int(os.getenv("ELASTICSEARCH_TIMEOUT", "10"))
ELASTICSEARCH_BULK_SIZE: int     = int(os.getenv("ELASTICSEARCH_BULK_SIZE", "100"))

# ─── Prometheus Metrics ───────────────────────────────────────────────────────
METRICS_PORT: int       = int(os.getenv("METRICS_PORT", "8001"))
DASHBOARD_ORIGIN: str   = os.getenv("DASHBOARD_ORIGIN", "http://localhost:3001")

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR: str        = os.getenv("LOG_DIR", "logs")
APP_LOG_PATH: str   = os.path.join(LOG_DIR, "app.log")
ALERT_LOG_PATH: str = os.path.join(LOG_DIR, "alerts.log")
LOG_LEVEL: str      = os.getenv("LOG_LEVEL", "INFO")

# ─── Traffic Filtering ────────────────────────────────────────────────────────
TARGET_IPS: list    = [ip.strip() for ip in os.getenv("TARGET_IPS", "").split(",") if ip.strip()]

# ─── Detection thresholds ─────────────────────────────────────────────────────
ANOMALY_THRESHOLD: float  = float(os.getenv("ANOMALY_THRESHOLD", "-0.5"))
RISK_HIGH_THRESHOLD: int  = int(os.getenv("RISK_HIGH_THRESHOLD", "75"))
RISK_MED_THRESHOLD: int   = int(os.getenv("RISK_MED_THRESHOLD", "40"))

# ─── Alerting & Threat Intel ──────────────────────────────────────────────────
SLACK_WEBHOOK_URL: str  = os.getenv("SLACK_WEBHOOK_URL", "")
EMAIL_SMTP_HOST: str    = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
EMAIL_SMTP_PORT: int    = int(os.getenv("EMAIL_SMTP_PORT", "587"))
EMAIL_SENDER: str       = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD: str     = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS: list  = os.getenv("EMAIL_RECIPIENTS", "").split(",")

VT_API_KEY: str         = os.getenv("VT_API_KEY", "")
OTX_API_KEY: str        = os.getenv("OTX_API_KEY", "")

# ─── API ──────────────────────────────────────────────────────────────────────
API_HOST: str    = os.getenv("API_HOST", "0.0.0.0")
API_PORT: int    = int(os.getenv("API_PORT", "8000"))
API_DEBUG: bool  = os.getenv("API_DEBUG", "false").lower() == "true"
API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "change-me-in-production")

# ─── Zeek ─────────────────────────────────────────────────────────────────────
ZEEK_LOG_DIR: str = os.getenv("ZEEK_LOG_DIR", "/var/log/zeek/current")
ZEEK_CONN_LOG: str = os.path.join(ZEEK_LOG_DIR, "conn.log")
