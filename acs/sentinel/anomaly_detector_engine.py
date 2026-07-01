"""
anomaly_detector_engine.py — Isolation Forest Anomaly Detection Engine

Uses a hybrid approach: rule-based detection for obvious attacks and
Isolation Forest for subtle statistical anomalies.

Features are generalised universal network traffic attributes so this engine
can be attached to any application log stream without modification.
"""

import os
import pickle
import numpy as np
from datetime import datetime

MODEL_PATH  = "model/isolation_forest.pkl"
SCALER_PATH = "model/scaler.pkl"

# Isolation Forest decision-function threshold.
# Scores below this value are treated as anomalies.
IF_THRESHOLD = 0.031

ENABLE_RULES = True

FEATURE_COLS = [
    "total_requests",
    "failed_status_rate",
    "payload_size_variance",
]

# ── Rule-Based Detection ──────────────────────────────────────────────────────
RULES = [
    ("failed_status_rate",    0.5,  "High rate of failed HTTP statuses",                     "HIGH"),
    ("total_requests",        60,   "Elevated request rate",                                  "HIGH"),
    ("total_requests",        300,  "Severe DDoS Flood",                                      "CRITICAL"),
    ("payload_size_variance", 1e10, "High payload size variance (possible fuzzing/exfiltration)", "HIGH"),
]


def rule_based_check(features: dict) -> dict | None:
    triggered        = []
    highest_severity = "NONE"
    severity_rank    = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    categories       = set()

    for col, threshold, label, severity in RULES:
        val = features.get(col, 0)
        if val >= threshold:
            triggered.append(f"{label} ({col}={val:.2f})")
            if severity_rank[severity] > severity_rank[highest_severity]:
                highest_severity = severity
            if "status" in col:
                categories.add("failure")
            if "requests" in col:
                categories.add("volume")
            if "payload" in col:
                categories.add("payload")

    # Combined multi-vector attack escalates to CRITICAL
    if len(categories) >= 2:
        highest_severity = "CRITICAL"
        triggered.append("Multi-Vector Traffic Anomaly Detected")

    if triggered:
        score_map   = {"LOW": -0.3, "MEDIUM": -0.6, "HIGH": -0.8, "CRITICAL": -1.0}
        final_score = score_map.get(highest_severity, -0.5)
        return {
            "is_anomaly":  True,
            "score":       final_score,
            "threshold":   0.0,
            "reason":      "; ".join(triggered),
            "method":      "rule",
            "severity":    highest_severity,
            "geo_anomaly": int(features.get("geo_anomaly", 0)),
            "timestamp":   datetime.utcnow().isoformat(),
        }
    return None


# ── Synthetic Training Data ───────────────────────────────────────────────────

def _generate_normal_samples(n: int = 2000) -> np.ndarray:
    rng = np.random.default_rng(42)
    return np.column_stack([
        rng.integers(1, 15, n),        # total_requests
        rng.uniform(0.0, 0.05, n),     # failed_status_rate
        rng.uniform(0, 100_000, n),    # payload_size_variance
    ]).astype(np.float64)


def _generate_attack_samples(n: int = 200) -> np.ndarray:
    rng     = np.random.default_rng(99)
    samples = []
    for _ in range(n):
        attack_type = rng.integers(0, 3)
        if attack_type == 0:
            samples.append([rng.integers(100, 500), rng.uniform(0.0, 0.1), rng.uniform(0, 200_000)])
        elif attack_type == 1:
            samples.append([rng.integers(20, 100),  rng.uniform(0.5, 1.0), rng.uniform(0, 100_000)])
        else:
            samples.append([rng.integers(5, 50),    rng.uniform(0.0, 0.2), rng.uniform(1e9, 1e11)])
    return np.array(samples, dtype=np.float64)


# ── Engine ────────────────────────────────────────────────────────────────────

class AnomalyDetectorEngine:

    def __init__(self):
        os.makedirs("model", exist_ok=True)
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                self._load()
                if self.scaler.mean_.shape[0] != len(FEATURE_COLS):
                    raise ValueError("Feature dimension mismatch — retraining.")
            except Exception as exc:
                print(f"  [AnomalyEngine] {exc}")
                self._train()
        else:
            print("  [AnomalyEngine] No saved model — training on synthetic data...")
            self._train()

    def _train(self):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        X = np.vstack([_generate_normal_samples(2000), _generate_attack_samples(200)])
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)
        self.model  = IsolationForest(
            n_estimators=300,
            max_samples="auto",
            contamination=0.10,
            random_state=42,
        )
        self.model.fit(X_scaled)
        self._save()
        print(f"  [AnomalyEngine] Model trained and saved -> {MODEL_PATH}")

    def _save(self):
        with open(MODEL_PATH,  "wb") as f:
            pickle.dump(self.model,  f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)

    def _load(self):
        with open(MODEL_PATH,  "rb") as f:
            self.model  = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)
        print(f"  [AnomalyEngine] Model loaded from {MODEL_PATH}")

    def score(self, features: dict) -> dict:
        if ENABLE_RULES:
            rule_result = rule_based_check(features)
            if rule_result:
                return rule_result

        vec        = np.array([[features.get(col, 0) for col in FEATURE_COLS]], dtype=np.float64)
        vec_scaled = self.scaler.transform(vec)
        score      = float(self.model.decision_function(vec_scaled)[0])
        is_anomaly = score < IF_THRESHOLD

        severity = "NONE"
        if is_anomaly:
            severity = "HIGH" if score < -0.2 else "MEDIUM"

        return {
            "is_anomaly":  is_anomaly,
            "score":       round(score, 6),
            "threshold":   IF_THRESHOLD,
            "reason":      self._explain(features, score) if is_anomaly else "",
            "method":      "isolation_forest",
            "severity":    severity,
            "geo_anomaly": int(features.get("geo_anomaly", 0)),
            "timestamp":   datetime.utcnow().isoformat(),
        }

    def _explain(self, f: dict, score: float) -> str:
        reasons = []
        if f.get("failed_status_rate", 0) > 0.3:
            reasons.append("Suspicious HTTP failure rate (%.1f%%)" % (f["failed_status_rate"] * 100))
        if f.get("total_requests", 0) > 50:
            reasons.append("Elevated request volume (%d)" % f["total_requests"])
        if f.get("payload_size_variance", 0) > 1e9:
            reasons.append("Anomalous payload size variance")
        if f.get("geo_anomaly", 0) == 1:
            reasons.append("Non-Malaysian IP address")
        if not reasons:
            reasons.append("Statistical anomaly (score=%.4f)" % score)
        return "; ".join(reasons)

    def retrain(self, X: np.ndarray):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)
        self.model  = IsolationForest(n_estimators=300, contamination=0.10, random_state=42)
        self.model.fit(X_scaled)
        self._save()
        print("  [AnomalyEngine] Retrained and saved.")
