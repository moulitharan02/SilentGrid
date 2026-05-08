"""
Offline ML training script — nt-traffic-filter (Phase 2).

Trains:
  • StandardScaler           → models/scaler.pkl
  • IsolationForest          → models/anomaly.pkl
  • RandomForestClassifier   → models/classifier.pkl AND models/rf_model.onnx
  • XGBoostClassifier        → models/xgboost_model.onnx

Usage:
    python training/train.py --data data/cicids.csv
"""

from __future__ import annotations

import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

# ONNX exports
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnxmltools

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config.config import (
    ANOMALY_MODEL_PATH,
    CLASSIFIER_MODEL_PATH,
    SCALER_PATH,
    MODEL_DIR,
    XGBOOST_MODEL_PATH,
    RF_ONNX_PATH,
)
from src.features.feature_engine import FEATURE_NAMES

# CICIDS-2017 column name mappings → our internal feature names
_COL_MAP = {
    " Flow Duration":         "duration",
    " Protocol":              "protocol_num",
    " Source Port":           "src_port",
    " Destination Port":      "dst_port",
    " Total Length of Fwd Packets": "orig_bytes",
    " Total Length of Bwd Packets": "resp_bytes",
    " Total Fwd Packets":     "orig_pkts",
    " Total Backward Packets": "resp_pkts",
    " Fwd Header Length":     "orig_ip_bytes",
    " Bwd Header Length":     "resp_ip_bytes",
    " Average Packet Size":   "bytes_per_pkt",
    " Flow Packets/s":        "pkt_rate",
    " Flow Bytes/s":          "byte_rate",
    " Label":                 "label",
}

def load_data(csv_path: str) -> pd.DataFrame:
    print(f"[+] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False, comment="#")
    df.rename(columns=_COL_MAP, inplace=True)

    # Keep only mapped columns
    keep = FEATURE_NAMES + ["label"]
    df = df[[c for c in keep if c in df.columns]]

    # Sanitise
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    print(f"    Rows loaded : {len(df):,}")
    print(f"    Labels      : {df['label'].value_counts().to_dict()}")
    return df

def train(csv_path: str) -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = load_data(csv_path)
    X  = df[FEATURE_NAMES].astype(float).values
    y  = df["label"].values

    # Convert labels to categorical for XGBoost
    unique_labels = np.unique(y)
    label_map = {l: i for i, l in enumerate(unique_labels)}
    y_encoded = np.array([label_map[l] for l in y])

    # Save the label map for decoding during inference
    joblib.dump(label_map, os.path.join(MODEL_DIR, "label_map.pkl"))

    # ── Scaler ────────────────────────────────────────────────────────────────
    print("\n[+] Fitting StandardScaler …")
    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_PATH)
    print(f"    Saved → {SCALER_PATH}")

    # ── Anomaly detector (trained on BENIGN only) ─────────────────────────────
    print("\n[+] Training IsolationForest (anomaly detector) …")
    benign_mask = y == "BENIGN"
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled[benign_mask])
    joblib.dump(iso, ANOMALY_MODEL_PATH)
    print(f"    Trained on {benign_mask.sum():,} BENIGN samples — saved → {ANOMALY_MODEL_PATH}")

    # ── Splits ────────────────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=0.20, random_state=42
    )

    # ── Multi-class classifier (RandomForest) ─────────────────────────────────
    print("\n[+] Training RandomForestClassifier (multi-class) …")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, CLASSIFIER_MODEL_PATH)
    print(f"    Saved PKL → {CLASSIFIER_MODEL_PATH}")

    # Export RF to ONNX
    initial_type = [('float_input', FloatTensorType([None, X_scaled.shape[1]]))]
    rf_onnx = convert_sklearn(rf, initial_types=initial_type, target_opset=12)
    with open(RF_ONNX_PATH, "wb") as f:
        f.write(rf_onnx.SerializeToString())
    print(f"    Saved ONNX → {RF_ONNX_PATH}")

    print("\n[+] Evaluation (RandomForest):")
    y_pred_rf = rf.predict(X_test)
    print(classification_report(y_test, y_pred_rf, zero_division=0, target_names=unique_labels))

    # ── Multi-class classifier (XGBoost) ──────────────────────────────────────
    print("\n[+] Training XGBoostClassifier (multi-class) …")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)

    # Export XGBoost to ONNX
    xgb_onnx = onnxmltools.convert_xgboost(xgb_model, initial_types=initial_type, target_opset=12)
    with open(XGBOOST_MODEL_PATH, "wb") as f:
        f.write(xgb_onnx.SerializeToString())
    print(f"    Saved ONNX → {XGBOOST_MODEL_PATH}")

    print("\n[+] Evaluation (XGBoost):")
    y_pred_xgb = xgb_model.predict(X_test)
    print(classification_report(y_test, y_pred_xgb, zero_division=0, target_names=unique_labels))

    print("\n✅  All Phase 2 models trained and saved to", MODEL_DIR)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train nt-traffic-filter ML models (Phase 2)")
    p.add_argument(
        "--data",
        default="data/cicids.csv",
        help="Path to the CICIDS-2017 CSV file (default: data/cicids.csv)",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train(args.data)
