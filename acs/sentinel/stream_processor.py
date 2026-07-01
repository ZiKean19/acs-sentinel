"""
acs/sentinel/stream_processor.py — Log Tail and Feature Extractor

Reads Nginx access.log, extracts 60-second sliding window features per IP,
and scores each event with the AnomalyDetectorEngine.

This module has NO dependency on Flask, the target app, or any HTTP calls.
It communicates back to main.py purely through callback functions.

On AWS: replace run_detection_loop() with a Lambda triggered by Kinesis.
"""

import os
import json
import time
import threading
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timezone

import boto3

LOCALSTACK_URL    = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
ACCESS_LOG_PATH   = os.environ.get("ACCESS_LOG_PATH", "/var/log/nginx/access.log")
POLL_INTERVAL     = 0.5
WINDOW_SECONDS    = 60
AWS_REGION        = "us-east-1"
ALERT_COOLDOWN_SEC = 60

_ip_alert_state   = {}
_alert_state_lock = threading.Lock()
SEVERITY_RANK     = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_AWS = dict(
    region_name=AWS_REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    endpoint_url=LOCALSTACK_URL,
)
dynamo_client = boto3.client("dynamodb", **_AWS)

# ── Sliding Window State ──────────────────────────────────────────────────────
ip_event_windows = defaultdict(deque)

MALAYSIAN_IP_PREFIXES = (
    "175.136.", "175.143.", "183.171.", "210.186.",
    "60.48.",   "49.128.",  "103.28.",  "115.164.",
    "127.",     "192.168.", "10.",      "172.",
)


def is_malaysian_ip(ip: str) -> bool:
    return any(ip.startswith(pfx) for pfx in MALAYSIAN_IP_PREFIXES)


def _purge_old(window: deque, now: float):
    cutoff = now - WINDOW_SECONDS
    while window and window[0][0] < cutoff:
        window.popleft()


def extract_features(ip: str, event: dict, now: float) -> dict:
    window = ip_event_windows[ip]
    _purge_old(window, now)
    window.append((now, event))

    events            = [e for _, e in window]
    total_requests    = len(events)
    failed            = sum(1 for e in events if int(e.get("status", 200)) >= 400)
    failed_status_rate = failed / total_requests if total_requests > 0 else 0.0
    sizes             = [float(e.get("payload_size", 0)) for e in events]
    payload_size_variance = float(np.var(sizes)) if len(sizes) > 1 else 0.0

    return {
        "ip":                    ip,
        "window_seconds":        WINDOW_SECONDS,
        "total_requests":        total_requests,
        "failed_status_rate":    round(failed_status_rate, 4),
        "payload_size_variance": round(payload_size_variance, 2),
        "geo_anomaly":           0 if is_malaysian_ip(ip) else 1,
    }


def _should_alert(ip: str, severity: str) -> bool:
    now = time.time()
    with _alert_state_lock:
        state = _ip_alert_state.get(ip)
        if state is None:
            _ip_alert_state[ip] = {"last_alerted": now, "last_severity": severity}
            return True
        time_since = now - state["last_alerted"]
        prev_rank  = SEVERITY_RANK.get(state["last_severity"], 0)
        curr_rank  = SEVERITY_RANK.get(severity, 0)
        if time_since >= ALERT_COOLDOWN_SEC:
            _ip_alert_state[ip] = {"last_alerted": now, "last_severity": severity}
            return True
        if curr_rank > prev_rank:
            _ip_alert_state[ip].update({"last_severity": severity, "last_alerted": now})
            return True
        return False


def _process_event(event: dict, detector, mitigator, on_log_cb):
    ip = event.get("ip", "")
    if not ip or ip in ("127.0.0.1", "::1"):
        return

    now      = time.time()
    features = extract_features(ip, event, now)
    result   = detector.score(features)

    method = event.get("method", "GET")
    uri    = event.get("uri", "/")
    status = event.get("status", 200)
    level  = "INFO"
    msg    = f"{method} {uri} -> HTTP {status}"

    if result["is_anomaly"]:
        level = result.get("severity", "MEDIUM")
        msg  += f" | {level} | score: {result['score']:.4f} | {result['reason']}"

    log_id    = f"{int(time.time() * 1000)}-{ip.replace('.', '-')}"
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "log_id":               log_id,
        "timestamp":            timestamp,
        "level":                level,
        "source":               "acs-sentinel",
        "message":              msg,
        "source_ip":            ip,
        "geo_anomaly":          features["geo_anomaly"],
        "score":                round(result.get("score", 0), 4),
    }

    # Push to dashboard via callback
    if on_log_cb:
        on_log_cb(log_entry)

    # Persist to DynamoDB asynchronously
    def _dynamo_log():
        try:
            dynamo_client.put_item(
                TableName="log-stream",
                Item={
                    "log_id":      {"S": log_id},
                    "timestamp":   {"S": timestamp},
                    "level":       {"S": level},
                    "source":      {"S": "acs-sentinel"},
                    "message":     {"S": msg},
                    "source_ip":   {"S": ip},
                    "geo_anomaly": {"N": str(features["geo_anomaly"])},
                    "score":       {"N": str(round(result.get("score", 0), 4))},
                },
            )
        except Exception:
            pass
    threading.Thread(target=_dynamo_log, daemon=True).start()

    # Console output
    ts    = datetime.now().strftime("%H:%M:%S")
    label = "[ANOMALY]" if result["is_anomaly"] else "[NORMAL ]"
    print(
        f"[{ts}] {label} | IP: {ip:>15} | "
        f"req={features['total_requests']:>3} | "
        f"fail={features['failed_status_rate']:>4.2f} | "
        f"var={features['payload_size_variance']:>10.0f} | "
        f"score={result['score']:.4f}"
    )

    if result["is_anomaly"]:
        severity = result.get("severity", "MEDIUM")
        if _should_alert(ip, severity):
            mitigator.respond(ip, features, result)


def _tail_file(filepath: str):
    print(f"  [ACS] Waiting for log file: {filepath}")
    while not os.path.exists(filepath):
        time.sleep(1)
    print(f"  [ACS] Tailing: {filepath}")
    with open(filepath, "r") as f:
        try:
            f.seek(0, 2)
        except Exception:
            pass
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            yield line


def run_detection_loop(detector, mitigator):
    """
    Main detection loop. Called from main.py in a background thread.
    On AWS this becomes a Lambda function triggered by Kinesis.
    """
    print("=" * 56)
    print("  ACS Sentinel — Detection Engine Starting")
    print(f"  Log source  : {ACCESS_LOG_PATH}")
    print(f"  Window      : {WINDOW_SECONDS}s sliding")
    print(f"  Alert dedup : {ALERT_COOLDOWN_SEC}s cooldown")
    print("=" * 56)

    on_log_cb = getattr(mitigator, "_on_log_cb", None)

    for line in _tail_file(ACCESS_LOG_PATH):
        try:
            event = json.loads(line.strip())
            _process_event(event, detector, mitigator, on_log_cb)
        except json.JSONDecodeError:
            pass
        except Exception as exc:
            print(f"  [ERROR] {exc}")
