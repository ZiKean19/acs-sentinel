"""
anomaly_detector_engine.py — Lambda version

Same hybrid rule + Isolation Forest logic as the local version, but the
model/scaler are loaded from S3 into /tmp (Lambda's writable ephemeral
storage) instead of a local ./model folder. If missing in S3, trains on
synthetic data and uploads them so future cold starts can just download.
"""

import os
import pickle
import boto3
import numpy as np
from datetime import datetime

MODEL_BUCKET = os.environ.get("MODEL_BUCKET", "acs-sentinel-models-teng")
MODEL_KEY    = "isolation_forest.pkl"
SCALER_KEY   = "scaler.pkl"
MODEL_PATH   = "/tmp/isolation_forest.pkl"
SCALER_PATH  = "/tmp/scaler.pkl"

IF_THRESHOLD  = -0.02
ENABLE_RULES  = True
FEATURE_COLS  = ["total_requests", "failed_status_rate", "payload_size_variance"]

RULES = [
    # Brute force is gated on the NUMBER of failed requests in the window, not a
    # bare failure rate. Rate alone means a single mistyped password (1 of 1
    # failed = 100%) trips the rule — real users fat-finger credentials, so that
    # is a false positive. Requiring a minimum count separates "a person having
    # a bad morning" (a handful) from automated credential stuffing (many).
    # Both thresholds are tuning knobs; the window is WINDOW_SECONDS (60s).
    ("failed_count",          5,    "Repeated failed requests",                                  "MEDIUM"),
    ("failed_count",          15,   "Brute force / credential stuffing",                         "HIGH"),
    ("total_requests",        60,   "Elevated request rate",                                     "HIGH"),
    ("total_requests",        300,  "Severe DDoS Flood",                                         "CRITICAL"),
    ("payload_size_variance", 1e10, "High payload size variance (possible fuzzing/exfiltration)", "HIGH"),
]

s3 = boto3.client("s3")


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
            if "status" in col or "failed" in col:
                categories.add("failure")
            if "requests" in col:
                categories.add("volume")
            if "payload" in col:
                categories.add("payload")

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


def _featurize(total_requests, failed_status_rate, payload_size_variance) -> list:
    """
    Build the model's feature vector.

    payload_size_variance spans ~0 to 1e11, while total_requests spans ~1-500
    and failed_status_rate spans 0-1. Left raw, the variance term dominates the
    scaled space and washes out the other two signals, so the model effectively
    only "sees" payload variance and treats moderate volume/failure anomalies as
    normal. A log1p transform compresses the variance range to a comparable
    scale, letting all three features contribute to the isolation score.
    """
    return [float(total_requests), float(failed_status_rate), float(np.log1p(payload_size_variance))]


def _generate_normal_samples(n: int = 2000) -> np.ndarray:
    rng = np.random.default_rng(42)
    return np.array([
        _featurize(r, f, p) for r, f, p in zip(
            rng.integers(1, 12, n),
            rng.uniform(0.0, 0.08, n),
            rng.uniform(0, 50_000, n),
        )
    ], dtype=np.float64)


def _generate_attack_samples(n: int = 400) -> np.ndarray:
    rng     = np.random.default_rng(99)
    samples = []
    for _ in range(n):
        attack_type = rng.integers(0, 4)
        if attack_type == 0:      # high-volume flood
            samples.append(_featurize(rng.integers(80, 500), rng.uniform(0.0, 0.15), rng.uniform(0, 200_000)))
        elif attack_type == 1:    # high failure rate (brute force / scanning)
            samples.append(_featurize(rng.integers(15, 100), rng.uniform(0.4, 1.0), rng.uniform(0, 80_000)))
        elif attack_type == 2:    # payload-size anomaly
            samples.append(_featurize(rng.integers(5, 50), rng.uniform(0.0, 0.3), rng.uniform(5e8, 1e11)))
        else:                     # moderate / low-and-slow anomaly — the class the
                                  # rule engine cannot catch, and the one the ML
                                  # exists to detect
            samples.append(_featurize(rng.integers(18, 60), rng.uniform(0.12, 0.4), rng.uniform(0, 100_000)))
    return np.array(samples, dtype=np.float64)


class AnomalyDetectorEngine:

    def __init__(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self._load_local()
            return
        try:
            s3.download_file(MODEL_BUCKET, MODEL_KEY, MODEL_PATH)
            s3.download_file(MODEL_BUCKET, SCALER_KEY, SCALER_PATH)
            self._load_local()
            print("[AnomalyEngine] Model loaded from S3.")
        except Exception as exc:
            print(f"[AnomalyEngine] No model in S3 ({exc}) — training fresh and uploading.")
            self._train()

    def _train(self):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        X = np.vstack([_generate_normal_samples(2000), _generate_attack_samples(400)])
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)
        self.model  = IsolationForest(n_estimators=300, max_samples="auto", contamination=0.10, random_state=42)
        self.model.fit(X_scaled)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self.scaler, f)

        try:
            s3.upload_file(MODEL_PATH, MODEL_BUCKET, MODEL_KEY)
            s3.upload_file(SCALER_PATH, MODEL_BUCKET, SCALER_KEY)
            print("[AnomalyEngine] Model trained and uploaded to S3.")
        except Exception as exc:
            print(f"[AnomalyEngine] Trained locally but S3 upload failed: {exc}")

    def _load_local(self):
        with open(MODEL_PATH, "rb") as f:
            self.model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)

    def score(self, features: dict) -> dict:
        if ENABLE_RULES:
            rule_result = rule_based_check(features)
            if rule_result:
                return rule_result

        # Must use the SAME featurisation as training (log1p on payload variance).
        vec        = np.array([_featurize(
            features.get("total_requests", 0),
            features.get("failed_status_rate", 0),
            features.get("payload_size_variance", 0),
        )], dtype=np.float64)
        vec_scaled = self.scaler.transform(vec)
        score      = float(self.model.decision_function(vec_scaled)[0])
        is_anomaly = score < IF_THRESHOLD

        # Four-band severity from the anomaly score. The lower (more negative)
        # the Isolation Forest score, the more isolated/abnormal the point, so
        # the higher the severity. A non-Malaysian source IP (geo_anomaly=1)
        # nudges the two lowest bands up one level, reflecting the SME threat
        # model where foreign traffic is somewhat more suspicious — without
        # collapsing every foreign hit into CRITICAL.
        # Bands are calibrated to the retrained model's score distribution:
        # benign traffic sits just above 0, and the score falls as the traffic
        # becomes more isolated (anomalous).
        severity = "NONE"
        if is_anomaly:
            if score < -0.085:
                severity = "CRITICAL"
            elif score < -0.065:
                severity = "HIGH"
            elif score < -0.040:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            if features.get("geo_anomaly", 0) == 1:
                bump = {"LOW": "MEDIUM", "MEDIUM": "HIGH"}
                severity = bump.get(severity, severity)

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
