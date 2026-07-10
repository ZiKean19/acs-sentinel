"""
lambda_function.py — ACS Sentinel Dashboard Lambda

Trigger: API Gateway HTTP API (payload format 2.0), Cognito JWT authorizer
attached at the API Gateway level (this Lambda assumes requests are
already authenticated by the time they arrive).

Routes:
  GET    /alerts
  GET    /blocked-ips
  DELETE /blocked-ips/{ip}
  GET    /logs
  POST   /telegram/webhook      (Telegram inline "Unblock" button callback)

Note: API Gateway + Lambda does not support long-lived Server-Sent Events
like the local Flask version. The React dashboard needs to switch from
useSSE (EventSource) to polling (e.g. re-fetch every 3-5s) when pointed
at this API. That swap lives in the frontend, not here.
"""

import os
import json
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

import boto3

AWS_REGION      = os.environ.get("AWS_REGION", "ap-southeast-1")
ALERTS_TABLE    = os.environ.get("ALERTS_TABLE", "alerts")
BLOCKLIST_TABLE = os.environ.get("BLOCKLIST_TABLE", "blocked-ips")
LOGSTREAM_TABLE = os.environ.get("LOGSTREAM_TABLE", "log-stream")
WAF_IPSET_ID    = os.environ.get("WAF_IPSET_ID", "")
WAF_IPSET_NAME  = os.environ.get("WAF_IPSET_NAME", "acs-blocked-ips")
WAF_IPSET_SCOPE = os.environ.get("WAF_IPSET_SCOPE", "REGIONAL")

TELEGRAM_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")

dynamo = boto3.client("dynamodb", region_name=AWS_REGION)
wafv2  = boto3.client("wafv2", region_name=AWS_REGION)

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,DELETE,POST,OPTIONS",
}


def _response(status: int, body) -> dict:
    return {
        "statusCode": status,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _get_alerts():
    resp  = dynamo.scan(TableName=ALERTS_TABLE, Limit=500)
    items = resp.get("Items", [])
    alerts = [{
        "alert_id":    i.get("alert_id", {}).get("S", ""),
        "timestamp":   i.get("timestamp", {}).get("S", ""),
        "source_ip":   i.get("source_ip", {}).get("S", ""),
        "severity":    i.get("severity", {}).get("S", "MEDIUM"),
        "type":        i.get("type", {}).get("S", "Unknown"),
        "score":       float(i.get("score", {}).get("N", 0)),
        "reason":      i.get("reason", {}).get("S", ""),
        "status":      i.get("status", {}).get("S", "OPEN"),
        "geo_anomaly": int(i.get("geo_anomaly", {}).get("N", 0)),
    } for i in items]
    return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)


def _get_blocked_ips():
    resp  = dynamo.scan(TableName=BLOCKLIST_TABLE, Limit=500)
    items = resp.get("Items", [])
    return [{
        "ip":          i.get("ip", {}).get("S", ""),
        "blocked_at":  i.get("blocked_at", {}).get("S", ""),
        "reason":      i.get("reason", {}).get("S", ""),
        "score":       float(i.get("score", {}).get("N", 0)),
        "ttl":         int(i.get("ttl", {}).get("N", 0)),
        "severity":    i.get("severity", {}).get("S", "MEDIUM"),
        "geo_anomaly": int(i.get("geo_anomaly", {}).get("N", 0)),
    } for i in items]


def _get_logs():
    resp  = dynamo.scan(TableName=LOGSTREAM_TABLE, Limit=500)
    items = resp.get("Items", [])
    logs = [{
        "log_id":      i.get("log_id", {}).get("S", ""),
        "timestamp":   i.get("timestamp", {}).get("S", ""),
        "level":       i.get("level", {}).get("S", "INFO"),
        "source":      i.get("source", {}).get("S", ""),
        "message":     i.get("message", {}).get("S", ""),
        "source_ip":   i.get("source_ip", {}).get("S", ""),
        "geo_anomaly": int(i.get("geo_anomaly", {}).get("N", 0)),
    } for i in items]
    all_logs   = sorted(logs, key=lambda x: x["timestamp"], reverse=True)
    audit_logs = [l for l in all_logs if l["level"] == "AUDIT"]
    other_logs = [l for l in all_logs if l["level"] != "AUDIT"][:100]
    return audit_logs + other_logs


def _remove_from_waf(ip: str):
    if not WAF_IPSET_ID:
        return
    try:
        resp = wafv2.get_ip_set(Name=WAF_IPSET_NAME, Scope=WAF_IPSET_SCOPE, Id=WAF_IPSET_ID)
        addresses = [a for a in resp["IPSet"]["Addresses"] if a != f"{ip}/32"]
        wafv2.update_ip_set(
            Name=WAF_IPSET_NAME, Scope=WAF_IPSET_SCOPE, Id=WAF_IPSET_ID,
            Addresses=addresses, LockToken=resp["LockToken"],
        )
    except Exception as exc:
        print(f"[WARN] WAF removal failed: {exc}")


def _unblock_ip(ip: str):
    try:
        dynamo.delete_item(TableName=BLOCKLIST_TABLE, Key={"ip": {"S": ip}})
    except Exception as exc:
        print(f"[ERROR] DynamoDB delete failed: {exc}")

    _remove_from_waf(ip)

    log_id = f"{int(time.time() * 1000)}-manual-unblock"
    try:
        dynamo.put_item(
            TableName=LOGSTREAM_TABLE,
            Item={
                "log_id":      {"S": log_id},
                "timestamp":   {"S": datetime.now(timezone.utc).isoformat()},
                "level":       {"S": "AUDIT"},
                "source":      {"S": "acs-dashboard"},
                "message":     {"S": f"UNBLOCKED {ip} — manual dashboard override"},
                "source_ip":   {"S": ip},
                "geo_anomaly": {"N": "0"},
            },
        )
    except Exception as exc:
        print(f"[ERROR] Audit log write failed: {exc}")


def _answer_telegram_callback(callback_query_id: str, text: str):
    if not TELEGRAM_TOKEN:
        return
    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/answerCallbackQuery"
        data = urllib.parse.urlencode({"callback_query_id": callback_query_id, "text": text}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=5)
    except Exception as exc:
        print(f"[WARN] Telegram callback ack failed: {exc}")


def _handle_telegram_webhook(body_str: str):
    try:
        update = json.loads(body_str or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid payload"})

    callback = update.get("callback_query")
    if callback and callback.get("data", "").startswith("unblock:"):
        ip = callback["data"].split("unblock:", 1)[1]
        _unblock_ip(ip)
        _answer_telegram_callback(callback["id"], f"Unblocked {ip}")

    return _response(200, {"ok": True})


def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", event.get("httpMethod", "GET"))
    path   = event.get("rawPath", event.get("path", "/"))
    path_params = event.get("pathParameters") or {}

    if method == "OPTIONS":
        return _response(200, {})

    try:
        if path == "/alerts" and method == "GET":
            return _response(200, _get_alerts())

        if path == "/blocked-ips" and method == "GET":
            return _response(200, _get_blocked_ips())

        if path.startswith("/blocked-ips/") and method == "DELETE":
            ip = path_params.get("ip") or path.split("/blocked-ips/", 1)[1]
            ip = urllib.parse.unquote(ip)
            _unblock_ip(ip)
            return _response(200, {"status": "unblocked", "ip": ip})

        if path == "/logs" and method == "GET":
            return _response(200, _get_logs())

        if path == "/telegram/webhook" and method == "POST":
            return _handle_telegram_webhook(event.get("body", "{}"))

        if path == "/health":
            return _response(200, {"status": "ok", "service": "acs-sentinel-dashboard"})

        return _response(404, {"error": "not found"})

    except Exception as exc:
        print(f"[ERROR] {exc}")
        return _response(500, {"error": str(exc)})
