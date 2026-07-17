"""
lambda_function.py — ACS Sentinel Dashboard Lambda

Trigger: API Gateway HTTP API (payload format 2.0). Cognito JWT authorizer
attached at the API Gateway level for every route EXCEPT /telegram/webhook —
Telegram's servers cannot present a Cognito JWT, so that one route must have
its authorizer set to NONE and is instead authenticated with Telegram's
secret_token header (see _handle_telegram_webhook).

Routes:
  GET    /alerts
  GET    /blocked-ips
  DELETE /blocked-ips/{ip}
  GET    /logs?limit=&cursor=&q=      (paginated, newest first, searchable)
  POST   /telegram/webhook            (inline "Unblock" button callback)
  GET    /health

Log pagination design (budget-aware):
  The log-stream table is keyed on log_id, so a time-ordered read used to mean
  Scan + sort + truncate to 100 — which is both the "only 100 logs" limit the
  dashboard hit and, as the table grows, a full-table read every 4-second poll.
  A GSI ("by-time": gsi_pk = constant "LOG", sort key = timestamp) turns that
  into a Query that reads ONLY the rows it returns, newest first:

    - poll:        Query latest N (default 300)          — cheap forever
    - load older:  Query with ExclusiveStartKey (cursor) — correct time order
    - search:      Query pages server-side, filter case-insensitively in
                   Python, return matches + cursor so the client can continue

  If the GSI does not exist yet the code falls back to the legacy Scan path,
  so deploying this Lambda before creating the index degrades gracefully
  instead of breaking the dashboard.
"""

import os
import json
import time
import base64
import urllib.request
import urllib.parse
from datetime import datetime, timezone

import boto3

AWS_REGION      = os.environ.get("AWS_REGION", "ap-southeast-1")
ALERTS_TABLE    = os.environ.get("ALERTS_TABLE", "alerts")
BLOCKLIST_TABLE = os.environ.get("BLOCKLIST_TABLE", "blocked-ips")
LOGSTREAM_TABLE = os.environ.get("LOGSTREAM_TABLE", "log-stream")
LOGS_GSI        = os.environ.get("LOGS_GSI", "by-time")
WAF_IPSET_ID    = os.environ.get("WAF_IPSET_ID", "")
WAF_IPSET_NAME  = os.environ.get("WAF_IPSET_NAME", "acs-blocked-ips")
WAF_IPSET_SCOPE = os.environ.get("WAF_IPSET_SCOPE", "REGIONAL")

TELEGRAM_TOKEN          = os.environ.get("TELEGRAM_BOT_TOKEN", "")
# Random string you choose at setWebhook time. Telegram echoes it back in the
# X-Telegram-Bot-Api-Secret-Token header on every webhook call; anything that
# arrives without it is not Telegram and gets a 403.
TELEGRAM_WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")

GSI_PK = "LOG"                # constant partition key of the by-time index
POLL_LIMIT_DEFAULT = 300      # newest rows returned to the 4s poll
PAGE_LIMIT_MAX     = 500      # hard cap per request
SEARCH_QUERY_PAGES = 8        # DynamoDB pages walked per search request

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


# ── Alerts / blocklist (small, bounded tables — a capped scan stays fine) ────

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
        # `method` distinguishes ML detections from rule hits. It was omitted
        # here, so the dashboard saw undefined and labelled every alert "Rule",
        # rendering the Isolation Forest invisible in the UI.
        "method":      i.get("method", {}).get("S", ""),
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


# ── Logs: paginated, newest-first, searchable ────────────────────────────────

def _log_from_item(i: dict) -> dict:
    entry = {
        "log_id":      i.get("log_id", {}).get("S", ""),
        "timestamp":   i.get("timestamp", {}).get("S", ""),
        "level":       i.get("level", {}).get("S", "INFO"),
        "source":      i.get("source", {}).get("S", ""),
        "message":     i.get("message", {}).get("S", ""),
        "source_ip":   i.get("source_ip", {}).get("S", ""),
        "geo_anomaly": int(i.get("geo_anomaly", {}).get("N", 0)),
    }
    # `score` was previously dropped in this projection, which is why the
    # dashboard's baseline chart could never see log scores. Pass it through
    # as a real number (never a string — the frontend rejects string scores).
    if "score" in i and "N" in i["score"]:
        try:
            entry["score"] = float(i["score"]["N"])
        except (TypeError, ValueError):
            pass
    return entry


def _encode_cursor(lek):
    if not lek:
        return None
    return base64.urlsafe_b64encode(json.dumps(lek).encode()).decode()


def _decode_cursor(cursor):
    if not cursor:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        return None  # a garbled cursor restarts from the newest page


def _matches(entry: dict, needle: str) -> bool:
    hay = f"{entry['timestamp']} {entry['level']} {entry['source_ip']} {entry['message']} {entry['source']}".lower()
    return needle in hay


def _query_logs_page(limit, cursor, q):
    """Time-ordered page via the by-time GSI. Raises if the index is missing."""
    needle = (q or "").strip().lower()
    lek    = _decode_cursor(cursor)
    items: list = []
    scanned = 0

    # Plain paging reads exactly one page sized to the limit. A search walks
    # up to SEARCH_QUERY_PAGES pages per request so one Lambda call does a
    # bounded amount of work; the returned cursor lets the client continue.
    pages      = SEARCH_QUERY_PAGES if needle else 1
    page_limit = 400 if needle else limit

    for _ in range(pages):
        kwargs = {
            "TableName":                 LOGSTREAM_TABLE,
            "IndexName":                 LOGS_GSI,
            "KeyConditionExpression":    "gsi_pk = :p",
            "ExpressionAttributeValues": {":p": {"S": GSI_PK}},
            "ScanIndexForward":          False,   # newest first
            "Limit":                     page_limit,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp  = dynamo.query(**kwargs)
        batch = [_log_from_item(i) for i in resp.get("Items", [])]
        scanned += len(batch)
        if needle:
            batch = [e for e in batch if _matches(e, needle)]
        items.extend(batch)
        lek = resp.get("LastEvaluatedKey")
        if not lek or len(items) >= limit:
            break

    return items, _encode_cursor(lek), scanned


def _scan_logs_page(limit, cursor, q):
    """
    Legacy fallback for before the by-time GSI exists. Scan order is not time
    order, so each page is sorted for display but "older" pages may interleave;
    acceptable as a stopgap, and search still reaches the whole table.
    """
    needle = (q or "").strip().lower()
    lek    = _decode_cursor(cursor)
    kwargs = {"TableName": LOGSTREAM_TABLE, "Limit": max(limit, 200)}
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp  = dynamo.scan(**kwargs)
    items = [_log_from_item(i) for i in resp.get("Items", [])]
    scanned = len(items)
    if needle:
        items = [e for e in items if _matches(e, needle)]
    items.sort(key=lambda x: x["timestamp"], reverse=True)
    return items, _encode_cursor(resp.get("LastEvaluatedKey")), scanned


def _get_logs_page(limit, cursor, q):
    limit = max(1, min(limit, PAGE_LIMIT_MAX))
    try:
        return _query_logs_page(limit, cursor, q)
    except Exception as exc:
        # Most likely: GSI not created yet (ValidationException). Fall back
        # rather than blank the dashboard, and say so in the logs.
        print(f"[WARN] by-time GSI query failed ({exc}) — falling back to Scan")
        return _scan_logs_page(limit, cursor, q)


# ── Unblock (shared by dashboard DELETE and Telegram button) ─────────────────

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


def _unblock_ip(ip: str, actor: str = "dashboard"):
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
                "gsi_pk":      {"S": GSI_PK},   # keep audit rows on the by-time index
                "timestamp":   {"S": datetime.now(timezone.utc).isoformat()},
                "level":       {"S": "AUDIT"},
                "source":      {"S": "acs-dashboard"},
                "message":     {"S": f"UNBLOCKED {ip} — manual override via {actor}"},
                "source_ip":   {"S": ip},
                "geo_anomaly": {"N": "0"},
            },
        )
    except Exception as exc:
        print(f"[ERROR] Audit log write failed: {exc}")


# ── Telegram webhook ─────────────────────────────────────────────────────────

def _telegram_api(method: str, params: dict):
    if not TELEGRAM_TOKEN:
        return
    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/{method}"
        data = urllib.parse.urlencode(params).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=5)
    except Exception as exc:
        print(f"[WARN] Telegram {method} failed: {exc}")


def _handle_telegram_webhook(event):
    # Authenticate the caller. This route bypasses the Cognito authorizer
    # (Telegram cannot send a JWT), so the shared secret is the gate.
    headers = {(k or "").lower(): v for k, v in (event.get("headers") or {}).items()}
    if TELEGRAM_WEBHOOK_SECRET:
        if headers.get("x-telegram-bot-api-secret-token") != TELEGRAM_WEBHOOK_SECRET:
            return _response(403, {"error": "forbidden"})
    else:
        print("[WARN] TELEGRAM_WEBHOOK_SECRET not set — webhook is unauthenticated")

    try:
        update = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid payload"})

    callback = update.get("callback_query")
    if callback and callback.get("data", "").startswith("unblock:"):
        ip = callback["data"].split("unblock:", 1)[1]
        _unblock_ip(ip, actor="telegram")

        # Feedback in the chat itself, or the button looks dead even when it
        # worked: pop a toast on the tapper's screen, then rewrite the alert
        # message so the button disappears and the outcome is recorded inline.
        _telegram_api("answerCallbackQuery", {
            "callback_query_id": callback["id"],
            "text": f"Unblocked {ip}",
        })
        msg = callback.get("message") or {}
        chat_id    = (msg.get("chat") or {}).get("id")
        message_id = msg.get("message_id")
        if chat_id and message_id:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            _telegram_api("editMessageText", {
                "chat_id":    chat_id,
                "message_id": message_id,
                "text":       f"{msg.get('text', '')}\n\n\u2705 Unblocked via Telegram at {stamp}",
            })

    # Always 200: Telegram retries non-200 responses, which would replay the
    # same callback and re-trigger the unblock path.
    return _response(200, {"ok": True})


# ── Router ───────────────────────────────────────────────────────────────────

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
            _unblock_ip(ip, actor="dashboard")
            return _response(200, {"status": "unblocked", "ip": ip})

        if path == "/logs" and method == "GET":
            qsp    = event.get("queryStringParameters") or {}
            try:
                limit = int(qsp.get("limit", POLL_LIMIT_DEFAULT))
            except (TypeError, ValueError):
                limit = POLL_LIMIT_DEFAULT
            items, cursor, scanned = _get_logs_page(limit, qsp.get("cursor"), qsp.get("q"))
            return _response(200, {"items": items, "cursor": cursor, "scanned": scanned})

        if path == "/telegram/webhook" and method == "POST":
            return _handle_telegram_webhook(event)

        if path == "/health":
            return _response(200, {"status": "ok", "service": "acs-sentinel-dashboard"})

        return _response(404, {"error": "not found"})

    except Exception as exc:
        print(f"[ERROR] {exc}")
        return _response(500, {"error": str(exc)})
