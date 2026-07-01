"""
acs/sentinel/main.py — ACS Sentinel: Standalone Security Platform

This is the ONLY entry point for the entire ACS system.
It runs two things inside one process:
  1. A background thread that tails Nginx access.log, extracts features,
     scores with Isolation Forest, and triggers mitigations.
  2. A Flask web server that serves the security dashboard and all its APIs.

Integration contract with any target application:
  - The target app sends structured JSON logs to AWS CloudWatch Logs.
  - Nginx (configured by ACS) sits in front of the target app.
  - Nginx writes access logs to the shared volume this process reads.
  - That is the ONLY coupling. The target app needs zero ACS code.

On AWS deployment:
  - Replace the log-tail loop with a Kinesis trigger (Lambda).
  - Replace LocalStack endpoints with real AWS service URLs.
  - Host this dashboard on AWS Amplify or behind API Gateway.
"""

import os
import json
import time
import uuid
import queue
import socket
import threading
from collections import deque
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from flask import Flask, jsonify, abort, Response, stream_with_context
from flask_cors import CORS

from anomaly_detector_engine import AnomalyDetectorEngine
from mitigation_handler import MitigationHandler
from stream_processor import run_detection_loop

# ── Flask Init ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://localhost:8080",
]}})

# ── AWS / LocalStack Clients ──────────────────────────────────────────────────
LOCALSTACK_URL = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
AWS_REGION     = "us-east-1"
_AWS = dict(
    region_name=AWS_REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    endpoint_url=LOCALSTACK_URL,
)
_fast_cfg = Config(connect_timeout=10, read_timeout=10,  retries={"max_attempts": 2})
_dash_cfg = Config(connect_timeout=10, read_timeout=30,  retries={"max_attempts": 1})

dynamo_client = boto3.client("dynamodb", **_AWS, config=_fast_cfg)
dash_dynamo   = boto3.client("dynamodb", **_AWS, config=_dash_cfg)

BLOCKLIST_TABLE = "blocked-ips"

# ── In-Memory SSE Ring Buffers ────────────────────────────────────────────────
MAX_CACHE     = 5000
alerts_cache  : deque = deque(maxlen=MAX_CACHE)
logs_cache    : deque = deque(maxlen=MAX_CACHE)
blocked_cache : deque = deque(maxlen=MAX_CACHE)

_alerts_subs  : list = []
_logs_subs    : list = []
_blocked_subs : list = []
_cache_lock   = threading.Lock()


def push_event(cache: deque, subs: list, event_type: str, payload):
    """Push a new event into a ring buffer and broadcast to all SSE clients."""
    msg = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
    with _cache_lock:
        if event_type == "replace":
            cache.clear()
            if isinstance(payload, list):
                cache.extend(payload)
        else:
            cache.appendleft(payload)
        dead = []
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            try:
                subs.remove(q)
            except ValueError:
                pass


def _sse_stream(subs: list, cache: deque):
    q: queue.Queue = queue.Queue(maxsize=200)
    with _cache_lock:
        snapshot = list(cache)
        subs.append(q)
    yield f"event: init\ndata: {json.dumps(snapshot)}\n\n"
    try:
        while True:
            try:
                msg = q.get(timeout=15)
                yield msg
            except queue.Empty:
                yield ": heartbeat\n\n"
    except GeneratorExit:
        pass
    finally:
        with _cache_lock:
            try:
                subs.remove(q)
            except ValueError:
                pass


# ── Public callbacks used by stream_processor and mitigation_handler ──────────

def on_new_alert(alert: dict):
    push_event(alerts_cache, _alerts_subs, "update", alert)


def on_new_log(log: dict):
    push_event(logs_cache, _logs_subs, "update", log)


def on_blocked_ip(ip_entry: dict):
    # Replace existing entry for the same IP if present
    with _cache_lock:
        existing = [x for x in blocked_cache if x.get("ip") != ip_entry.get("ip")]
        blocked_cache.clear()
        blocked_cache.extend(existing)
    push_event(blocked_cache, _blocked_subs, "update", ip_entry)


def on_unblocked_ip(ip: str):
    with _cache_lock:
        updated = [x for x in blocked_cache if x.get("ip") != ip]
        blocked_cache.clear()
        blocked_cache.extend(updated)
        snapshot = list(blocked_cache)
    msg = f"event: replace\ndata: {json.dumps(snapshot)}\n\n"
    for q in _blocked_subs:
        try:
            q.put_nowait(msg)
        except queue.Full:
            pass


# ── SSE Streaming Endpoints ───────────────────────────────────────────────────

@app.route("/stream/alerts")
def stream_alerts():
    return Response(
        stream_with_context(_sse_stream(_alerts_subs, alerts_cache)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/logs")
def stream_logs():
    return Response(
        stream_with_context(_sse_stream(_logs_subs, logs_cache)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/blocked-ips")
def stream_blocked_ips():
    return Response(
        stream_with_context(_sse_stream(_blocked_subs, blocked_cache)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Dashboard REST Endpoints ──────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "acs-sentinel"})


@app.route("/alerts")
def get_alerts():
    try:
        resp  = dash_dynamo.scan(TableName="alerts", Limit=500)
        items = resp.get("Items", [])
        alerts = [
            {
                "alert_id":    item.get("alert_id",  {}).get("S", ""),
                "timestamp":   item.get("timestamp", {}).get("S", ""),
                "source_ip":   item.get("source_ip", {}).get("S", ""),
                "severity":    item.get("severity",  {}).get("S", "MEDIUM"),
                "type":        item.get("type",       {}).get("S", "Unknown"),
                "score":       float(item.get("score", {}).get("N", 0)),
                "reason":      item.get("reason",     {}).get("S", ""),
                "status":      item.get("status",     {}).get("S", "OPEN"),
                "geo_anomaly": int(item.get("geo_anomaly", {}).get("N", 0)),
            }
            for item in items
        ]
        return jsonify(sorted(alerts, key=lambda x: x["timestamp"], reverse=True))
    except Exception as exc:
        app.logger.error(f"Alerts fetch error: {exc}")
        return jsonify([])


@app.route("/blocked-ips")
def get_blocked_ips():
    try:
        resp  = dash_dynamo.scan(TableName="blocked-ips", Limit=500)
        items = resp.get("Items", [])
        ips = [
            {
                "ip":          item.get("ip",         {}).get("S", ""),
                "blocked_at":  item.get("blocked_at", {}).get("S", ""),
                "reason":      item.get("reason",     {}).get("S", ""),
                "score":       float(item.get("score", {}).get("N", 0)),
                "ttl":         int(item.get("ttl",    {}).get("N", 0)),
                "severity":    item.get("severity",   {}).get("S", "MEDIUM"),
                "geo_anomaly": int(item.get("geo_anomaly", {}).get("N", 0)),
            }
            for item in items
        ]
        return jsonify(ips)
    except Exception as exc:
        app.logger.error(f"Blocked IPs fetch error: {exc}")
        return jsonify([])


@app.route("/blocked-ips/<path:ip>", methods=["DELETE"])
def delete_blocked_ip(ip: str):
    """Manual unblock from dashboard."""
    # 1. Remove from DynamoDB
    def _dynamo_delete():
        try:
            dynamo_client.delete_item(
                TableName=BLOCKLIST_TABLE,
                Key={"ip": {"S": ip}},
            )
        except Exception:
            pass
    threading.Thread(target=_dynamo_delete, daemon=True).start()

    # 2. Remove from Nginx blocklist file
    blocklist_path = os.environ.get("NGINX_BLOCKLIST_PATH", "/etc/nginx/blocked_ips.conf")
    if os.path.exists(blocklist_path):
        try:
            block_line = f"deny {ip};\n"
            with open(blocklist_path, "r") as f:
                lines = f.readlines()
            with open(blocklist_path, "w") as f:
                f.writelines(l for l in lines if l != block_line)
            _reload_nginx()
        except Exception as exc:
            app.logger.warning(f"Nginx reload error: {exc}")

    # 3. Update SSE cache
    log_id = f"{int(time.time() * 1000)}-manual-unblock"
    audit  = {
        "log_id":    log_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level":     "AUDIT",
        "source":    "acs-dashboard",
        "message":   f"UNBLOCKED {ip} — manual dashboard override",
        "source_ip": ip,
        "geo_anomaly": 0,
    }
    on_unblocked_ip(ip)
    on_new_log(audit)

    def _dynamo_audit():
        try:
            dynamo_client.put_item(
                TableName="log-stream",
                Item={
                    "log_id":      {"S": log_id},
                    "timestamp":   {"S": audit["timestamp"]},
                    "level":       {"S": "AUDIT"},
                    "source":      {"S": "acs-dashboard"},
                    "message":     {"S": audit["message"]},
                    "source_ip":   {"S": ip},
                    "geo_anomaly": {"N": "0"},
                },
            )
        except Exception:
            pass
    threading.Thread(target=_dynamo_audit, daemon=True).start()

    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/logs")
def get_logs():
    try:
        resp  = dash_dynamo.scan(TableName="log-stream", Limit=500)
        items = resp.get("Items", [])
        logs  = [
            {
                "log_id":      item.get("log_id",    {}).get("S", ""),
                "timestamp":   item.get("timestamp", {}).get("S", ""),
                "level":       item.get("level",     {}).get("S", "INFO"),
                "source":      item.get("source",    {}).get("S", ""),
                "message":     item.get("message",   {}).get("S", ""),
                "source_ip":   item.get("source_ip", {}).get("S", ""),
                "geo_anomaly": int(item.get("geo_anomaly", {}).get("N", 0)),
            }
            for item in items
        ]
        all_logs   = sorted(logs, key=lambda x: x["timestamp"], reverse=True)
        audit_logs = [l for l in all_logs if l["level"] == "AUDIT"]
        other_logs = [l for l in all_logs if l["level"] != "AUDIT"][:100]
        return jsonify(audit_logs + other_logs)
    except Exception as exc:
        app.logger.error(f"Logs fetch error: {exc}")
        return jsonify([])


# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": str(e.description)}), 403


# ── Nginx Reload Helper ───────────────────────────────────────────────────────

def _reload_nginx():
    try:
        if not os.path.exists("/var/run/docker.sock"):
            return
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect("/var/run/docker.sock")
        s.sendall(b"POST /containers/acs-nginx/kill?signal=HUP HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(1024)
        s.close()
    except Exception as exc:
        app.logger.warning(f"Nginx reload failed: {exc}")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start the detection loop in a background thread
    detector  = AnomalyDetectorEngine()
    mitigator = MitigationHandler(
        on_alert_cb=on_new_alert,
        on_log_cb=on_new_log,
        on_block_cb=on_blocked_ip,
        on_unblock_cb=on_unblocked_ip,
    )

    detection_thread = threading.Thread(
        target=run_detection_loop,
        args=(detector, mitigator),
        daemon=True,
        name="detection-loop",
    )
    detection_thread.start()
    print("  [ACS] Detection loop started in background thread.")
    print("  [ACS] Dashboard API listening on http://0.0.0.0:8080")

    # Serve the dashboard API
    app.run(debug=False, host="0.0.0.0", port=8080, threaded=True)
