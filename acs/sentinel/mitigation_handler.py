"""
acs/sentinel/mitigation_handler.py — Automated Threat Response Handler

Blocks IPs by writing to Nginx blocked_ips.conf and reloading Nginx.
Persists all blocks and alerts to DynamoDB.
Sends Telegram notifications with inline unblock button.

Uses callback functions (not HTTP calls) to notify the dashboard.
This makes the handler completely decoupled from the target application.
"""

import os
import json
import time
import socket
import threading
import urllib.request
import urllib.parse
import boto3
from datetime import datetime, timezone
from typing import Callable, Optional

NGINX_BLOCKLIST_PATH = os.environ.get("NGINX_BLOCKLIST_PATH", "/etc/nginx/blocked_ips.conf")
LOCALSTACK_URL       = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
AWS_REGION           = "us-east-1"
BLOCKLIST_TABLE      = "blocked-ips"

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

ALERT_COOLDOWN_SEC = 300

TTL_BY_SEVERITY = {
    "CRITICAL": 72 * 3600,
    "HIGH":     24 * 3600,
    "MEDIUM":    6 * 3600,
    "LOW":       1 * 3600,
}

_AWS = dict(
    region_name=AWS_REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    endpoint_url=LOCALSTACK_URL,
)
dynamo_client = boto3.client("dynamodb", **_AWS)


def _reload_nginx():
    try:
        if not os.path.exists("/var/run/docker.sock"):
            print("  [WARN] Docker socket not mounted — Nginx reload skipped.")
            return
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect("/var/run/docker.sock")
        s.sendall(b"POST /containers/acs-nginx/kill?signal=HUP HTTP/1.1\r\nHost: localhost\r\n\r\n")
        s.recv(1024)
        s.close()
        print("  [ACS] Nginx blocklist reloaded.")
    except Exception as exc:
        print(f"  [WARN] Nginx reload failed: {exc}")


def _classify_threat(features: dict, severity_hint: str = None) -> tuple:
    total_requests        = features.get("total_requests", 0)
    failed_status_rate    = features.get("failed_status_rate", 0)
    payload_size_variance = features.get("payload_size_variance", 0)
    geo_anomaly           = features.get("geo_anomaly", 0)

    if total_requests >= 300:
        threat_type = "DDoS Flood Attack"
    elif failed_status_rate >= 0.5:
        threat_type = "Brute Force / Scan Probe"
    elif payload_size_variance >= 1e10:
        threat_type = "Payload Injection / Fuzzing"
    elif total_requests >= 60:
        threat_type = "Rate Limit Violation"
    elif geo_anomaly == 1 and failed_status_rate >= 0.2:
        threat_type = "Foreign Scanner Anomaly"
    else:
        threat_type = "Traffic Pattern Anomaly"

    severity = severity_hint if severity_hint and severity_hint != "NONE" else "MEDIUM"
    return threat_type, severity


class MitigationHandler:

    def __init__(
        self,
        on_alert_cb:   Optional[Callable] = None,
        on_log_cb:     Optional[Callable] = None,
        on_block_cb:   Optional[Callable] = None,
        on_unblock_cb: Optional[Callable] = None,
    ):
        """
        Callbacks are injected by main.py so this handler can push events
        to the SSE dashboard without any HTTP coupling.
        """
        self._on_alert_cb   = on_alert_cb
        self._on_log_cb     = on_log_cb
        self._on_block_cb   = on_block_cb
        self._on_unblock_cb = on_unblock_cb
        self._alerted       = {}

    def respond(self, ip: str, features: dict, result: dict):
        severity = result.get("severity", "MEDIUM")
        print(f"\n  [MITIGATION] IP: {ip} | Severity: {severity}")
        print(f"     Reason: {result.get('reason', 'n/a')}")

        already_blocked = self._block_ip(ip, features, result)
        if already_blocked:
            print(f"     {ip} already blocked.")
        else:
            print(f"     {ip} added to blocklist.")

        self._write_alert(ip, features, result)
        self._send_telegram(ip, features, result)

    def _block_ip(self, ip: str, features: dict, result: dict) -> bool:
        block_line = f"deny {ip};\n"

        # Check if already in Nginx config
        if os.path.exists(NGINX_BLOCKLIST_PATH):
            with open(NGINX_BLOCKLIST_PATH, "r") as f:
                if block_line in f.readlines():
                    return True

        # Add to Nginx config and reload
        with open(NGINX_BLOCKLIST_PATH, "a") as f:
            f.write(block_line)
        _reload_nginx()

        threat_type, severity = _classify_threat(features, result.get("severity"))
        ttl_seconds = TTL_BY_SEVERITY.get(severity, 3600)
        blocked_entry = {
            "ip":          ip,
            "blocked_at":  datetime.now(timezone.utc).isoformat(),
            "reason":      result.get("reason", "ML anomaly"),
            "score":       result.get("score", 0),
            "geo_anomaly": features.get("geo_anomaly", 0),
            "severity":    severity,
            "ttl":         int(time.time()) + ttl_seconds,
        }

        # Notify dashboard via callback
        if self._on_block_cb:
            self._on_block_cb(blocked_entry)

        # Persist to DynamoDB
        def _dynamo():
            try:
                dynamo_client.put_item(
                    TableName=BLOCKLIST_TABLE,
                    Item={
                        "ip":          {"S": ip},
                        "blocked_at":  {"S": blocked_entry["blocked_at"]},
                        "reason":      {"S": blocked_entry["reason"]},
                        "score":       {"N": str(blocked_entry["score"])},
                        "source":      {"S": "acs-auto-block"},
                        "geo_anomaly": {"N": str(features.get("geo_anomaly", 0))},
                        "severity":    {"S": severity},
                        "ttl":         {"N": str(blocked_entry["ttl"])},
                    },
                )
            except Exception:
                pass
        threading.Thread(target=_dynamo, daemon=True).start()
        return False

    def _write_alert(self, ip: str, features: dict, result: dict):
        threat_type, severity = _classify_threat(features, result.get("severity"))
        alert_id  = str(int(time.time() * 1000))
        ts        = datetime.now(timezone.utc).isoformat()
        alert = {
            "alert_id":    alert_id,
            "timestamp":   ts,
            "source_ip":   ip,
            "severity":    severity,
            "type":        threat_type,
            "score":       result.get("score", 0),
            "reason":      result.get("reason", "ML anomaly"),
            "method":      result.get("method", "isolation_forest"),
            "status":      "OPEN",
            "geo_anomaly": features.get("geo_anomaly", 0),
        }

        # Notify dashboard via callback
        if self._on_alert_cb:
            self._on_alert_cb(alert)

        # Persist to DynamoDB
        def _dynamo():
            try:
                dynamo_client.put_item(
                    TableName="alerts",
                    Item={
                        "alert_id":    {"S": alert_id},
                        "timestamp":   {"S": ts},
                        "source_ip":   {"S": ip},
                        "severity":    {"S": severity},
                        "type":        {"S": threat_type},
                        "score":       {"N": str(alert["score"])},
                        "reason":      {"S": alert["reason"]},
                        "method":      {"S": alert["method"]},
                        "status":      {"S": "OPEN"},
                        "geo_anomaly": {"N": str(features.get("geo_anomaly", 0))},
                    },
                )
            except Exception:
                pass
        threading.Thread(target=_dynamo, daemon=True).start()

    def _send_telegram(self, ip: str, features: dict, result: dict):
        now = time.time()
        if now - self._alerted.get(ip, 0) < ALERT_COOLDOWN_SEC:
            return
        self._alerted[ip] = now

        threat_type, severity = _classify_threat(features, result.get("severity"))
        ts            = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        emoji         = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
        ttl_h         = TTL_BY_SEVERITY.get(severity, 3600) // 3600
        msg = (
            f"🚨 ACS Sentinel Alert\n"
            f"{'─'*28}\n"
            f"{emoji} Severity : {severity}\n"
            f"Threat    : {threat_type}\n"
            f"IP Blocked: {ip}\n"
            f"Time      : {ts}\n"
            f"Score     : {result.get('score', 'n/a')}\n"
            f"Reason    : {result.get('reason', 'ML anomaly')}\n"
            f"Expires   : {ttl_h}h\n"
            f"{'─'*28}\n"
            f"Requests  : {features.get('total_requests', 0)}\n"
            f"Fail rate : {features.get('failed_status_rate', 0):.2f}\n"
            f"Geo       : {'Foreign' if features.get('geo_anomaly') else 'Malaysian'}\n"
            f"{'─'*28}\n"
            f"Action: IP blocked in Nginx + DynamoDB\n"
        )

        if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
            reply_markup = {
                "inline_keyboard": [[
                    {"text": f"Unblock {ip}", "callback_data": f"unblock:{ip}"}
                ]]
            }
            try:
                url    = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
                params = {
                    "chat_id":      TELEGRAM_CHAT_ID,
                    "text":         msg,
                    "reply_markup": json.dumps(reply_markup),
                }
                payload = urllib.parse.urlencode(params).encode()
                urllib.request.urlopen(
                    urllib.request.Request(url, data=payload, method="POST"),
                    timeout=5,
                )
            except Exception:
                pass
        else:
            print("\n  [TELEGRAM FALLBACK]\n" + msg)

    def unblock_ip(self, ip: str):
        """Called by Telegram bot callback to unblock an IP remotely."""
        block_line = f"deny {ip};\n"
        if os.path.exists(NGINX_BLOCKLIST_PATH):
            with open(NGINX_BLOCKLIST_PATH, "r") as f:
                lines = f.readlines()
            with open(NGINX_BLOCKLIST_PATH, "w") as f:
                f.writelines(l for l in lines if l != block_line)
            _reload_nginx()

        try:
            dynamo_client.delete_item(
                TableName=BLOCKLIST_TABLE,
                Key={"ip": {"S": ip}},
            )
        except Exception:
            pass

        if self._on_unblock_cb:
            self._on_unblock_cb(ip)
