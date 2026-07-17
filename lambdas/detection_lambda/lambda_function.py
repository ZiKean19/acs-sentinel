"""
lambda_function.py — ACS Sentinel Detection Lambda

Trigger: Kinesis (security-stream)
Each Kinesis record = one CloudWatch Logs event forwarded by the
subscription filter (base64 + gzip encoded, standard CWL->Kinesis format).

For each log event:
  1. Extract per-IP sliding-window features (using DynamoDB as the window
     store, since Lambda has no persistent memory between invocations).
  2. Score with rule engine + Isolation Forest.
  3. On anomaly: write alert to DynamoDB, block IP (DynamoDB blocked-ips
     table + WAF IP Set update), send Telegram notification.
"""

import os
import io
import json
import gzip
import base64
import time
import uuid
import urllib.request
import urllib.parse
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from anomaly_detector_engine import AnomalyDetectorEngine

AWS_REGION       = os.environ.get("AWS_REGION", "ap-southeast-1")
MODEL_BUCKET     = os.environ.get("MODEL_BUCKET", "acs-sentinel-models-teng")
BLOCKLIST_TABLE  = os.environ.get("BLOCKLIST_TABLE", "blocked-ips")
ALERTS_TABLE     = os.environ.get("ALERTS_TABLE", "alerts")
LOGSTREAM_TABLE  = os.environ.get("LOGSTREAM_TABLE", "log-stream")
WINDOW_TABLE     = os.environ.get("WINDOW_TABLE", "ip-windows")       # new: per-IP rolling counters
WAF_IPSET_ID     = os.environ.get("WAF_IPSET_ID", "")                 # set once WAF IP Set is created
WAF_IPSET_NAME   = os.environ.get("WAF_IPSET_NAME", "acs-blocked-ips")
WAF_IPSET_SCOPE  = os.environ.get("WAF_IPSET_SCOPE", "REGIONAL")

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

WINDOW_SECONDS   = 60
ALERT_COOLDOWN   = 60

TTL_BY_SEVERITY = {
    "CRITICAL": 72 * 3600,
    "HIGH":     24 * 3600,
    "MEDIUM":    6 * 3600,
    "LOW":       1 * 3600,
}

# ── Geo-detection (MaxMind GeoLite2) ──────────────────────────────────────────
# The GeoLite2-Country database is stored in S3 alongside the model files and
# downloaded to /tmp on cold start (same pattern as the .pkl model). Any IP
# resolving to a country other than Malaysia is treated as a geo-anomaly.
#
# Private / reserved ranges (RFC1918, loopback) are always treated as local
# (geo_anomaly=0) since they cannot be geolocated and represent internal traffic.
GEO_DB_KEY   = "GeoLite2-Country.mmdb"
GEO_DB_PATH  = "/tmp/GeoLite2-Country.mmdb"
HOME_COUNTRY = "MY"  # ISO country code for Malaysia

_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.") + tuple(
    f"172.{octet}." for octet in range(16, 32)
)

_geo_reader = None  # lazy singleton across warm invocations

dynamo = boto3.client("dynamodb", region_name=AWS_REGION)
wafv2  = boto3.client("wafv2", region_name=AWS_REGION)
s3     = boto3.client("s3", region_name=AWS_REGION)

_engine = None  # lazy singleton across warm invocations


def _get_engine():
    global _engine
    if _engine is None:
        _engine = AnomalyDetectorEngine()
    return _engine


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _get_geo_reader():
    """Lazy-load the GeoLite2 reader, downloading the .mmdb from S3 if needed."""
    global _geo_reader
    if _geo_reader is not None:
        return _geo_reader
    try:
        import maxminddb
        if not os.path.exists(GEO_DB_PATH):
            s3.download_file(MODEL_BUCKET, GEO_DB_KEY, GEO_DB_PATH)
        _geo_reader = maxminddb.open_database(GEO_DB_PATH)
        print("[Geo] GeoLite2 database loaded.")
    except Exception as exc:
        print(f"[Geo] Could not load GeoLite2 DB ({exc}) — geo checks will treat IPs as local.")
        _geo_reader = False  # sentinel: tried and failed, don't retry every call
    return _geo_reader


def is_malaysian_ip(ip: str) -> bool:
    """
    True if the IP is Malaysian or a private/internal address.
    Uses MaxMind GeoLite2 for a real country lookup; falls back to treating
    the IP as local if the database is unavailable (fail-open, so a missing
    DB never causes a flood of false geo-anomalies).
    """
    if _is_private_ip(ip):
        return True
    reader = _get_geo_reader()
    if not reader:
        return True  # fail-open if DB unavailable
    try:
        result = reader.get(ip)
        if not result:
            return True  # not in DB (reserved/anycast) — treat as local
        iso = result.get("country", {}).get("iso_code")
        return iso == HOME_COUNTRY
    except Exception:
        return True


def _decode_kinesis_record(record) -> list:
    """CloudWatch Logs -> Kinesis records are base64 + gzip encoded JSON."""
    payload = base64.b64decode(record["kinesis"]["data"])
    try:
        decompressed = gzip.GzipFile(fileobj=io.BytesIO(payload)).read()
        data = json.loads(decompressed)
    except OSError:
        # Not gzipped (e.g. direct PutRecord in testing) — try raw JSON
        data = json.loads(payload)

    events = []
    if data.get("messageType") == "DATA_MESSAGE":
        for log_event in data.get("logEvents", []):
            try:
                events.append(json.loads(log_event["message"]))
            except (json.JSONDecodeError, KeyError):
                continue
    return events


def _decode_cwlogs_direct(event) -> list:
    """
    Direct CloudWatch Logs subscription (no Kinesis in between).
    The whole event is: {"awslogs": {"data": "<base64 gzip>"}}
    Decoded payload has the same DATA_MESSAGE / logEvents structure.
    """
    payload = base64.b64decode(event["awslogs"]["data"])
    decompressed = gzip.GzipFile(fileobj=io.BytesIO(payload)).read()
    data = json.loads(decompressed)

    events = []
    if data.get("messageType") == "DATA_MESSAGE":
        for log_event in data.get("logEvents", []):
            msg = log_event.get("message", "")
            try:
                # Our target app logs structured JSON lines.
                events.append(json.loads(msg))
            except (json.JSONDecodeError, TypeError):
                # Not JSON (e.g. a plain access log line) — skip.
                continue
    return events


def _get_window_counters(ip: str) -> dict:
    """
    Fetch the current rolling-window counters for this IP from DynamoDB.

    ConsistentRead is mandatory here. The window is a read-modify-write cycle,
    and DynamoDB's default eventually-consistent read can return a copy that is
    milliseconds stale. During a burst that silently undercounts
    total_requests, so the volume rules (>= 60, >= 300) never fire and every
    detection degrades to an ML-only MEDIUM/HIGH.
    """
    try:
        resp = dynamo.get_item(
            TableName=WINDOW_TABLE,
            Key={"ip": {"S": ip}},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return {"events": []}
        return {"events": json.loads(item.get("events_json", {}).get("S", "[]"))}
    except Exception as exc:
        print(f"[WARN] Could not read window state for {ip}: {exc}")
        return {"events": []}


def _save_window_counters(ip: str, events: list):
    ttl = int(time.time()) + WINDOW_SECONDS + 30
    try:
        dynamo.put_item(
            TableName=WINDOW_TABLE,
            Item={
                "ip":         {"S": ip},
                "events_json": {"S": json.dumps(events)},
                "ttl":        {"N": str(ttl)},
            },
        )
    except Exception as exc:
        print(f"[WARN] Could not save window state: {exc}")


def extract_features(ip: str, event: dict) -> dict:
    now = time.time()
    state  = _get_window_counters(ip)
    events = [e for e in state["events"] if now - e["t"] < WINDOW_SECONDS]
    events.append({
        "t":      now,
        "status": int(event.get("status", 200)) if str(event.get("status", "")).isdigit() else 200,
        "size":   float(event.get("payload_size", event.get("file_size", 0)) or 0),
    })
    _save_window_counters(ip, events)

    total_requests     = len(events)
    failed              = sum(1 for e in events if e["status"] >= 400)
    failed_status_rate  = failed / total_requests if total_requests else 0.0
    sizes                = [e["size"] for e in events]
    mean_sz               = sum(sizes) / len(sizes) if sizes else 0.0
    payload_size_variance = (sum((s - mean_sz) ** 2 for s in sizes) / len(sizes)) if len(sizes) > 1 else 0.0

    return {
        "ip":                    ip,
        "total_requests":        total_requests,
        "failed_status_rate":    round(failed_status_rate, 4),
        "payload_size_variance": round(payload_size_variance, 2),
        "geo_anomaly":           0 if is_malaysian_ip(ip) else 1,
    }


def _classify_threat(features: dict, severity_hint: str = None) -> str:
    total_requests        = features.get("total_requests", 0)
    failed_status_rate    = features.get("failed_status_rate", 0)
    payload_size_variance = features.get("payload_size_variance", 0)
    geo_anomaly           = features.get("geo_anomaly", 0)

    if total_requests >= 300:
        return "DDoS Flood Attack"
    if failed_status_rate >= 0.5:
        return "Brute Force / Scan Probe"
    if payload_size_variance >= 1e10:
        return "Payload Injection / Fuzzing"
    if total_requests >= 60:
        return "Rate Limit Violation"
    if geo_anomaly == 1 and failed_status_rate >= 0.2:
        return "Foreign Scanner Anomaly"
    return "Traffic Pattern Anomaly"


def _write_alert(ip: str, features: dict, result: dict):
    alert_id = str(int(time.time() * 1000)) + "-" + uuid.uuid4().hex[:6]
    ts       = datetime.now(timezone.utc).isoformat()
    threat   = _classify_threat(features, result.get("severity"))
    try:
        dynamo.put_item(
            TableName=ALERTS_TABLE,
            Item={
                "alert_id":    {"S": alert_id},
                "timestamp":   {"S": ts},
                "source_ip":   {"S": ip},
                "severity":    {"S": result.get("severity", "MEDIUM")},
                "type":        {"S": threat},
                "score":       {"N": str(result.get("score", 0))},
                "reason":      {"S": result.get("reason", "")},
                "method":      {"S": result.get("method", "isolation_forest")},
                "status":      {"S": "OPEN"},
                "geo_anomaly": {"N": str(features.get("geo_anomaly", 0))},
            },
        )
    except Exception as exc:
        print(f"[ERROR] Failed to write alert: {exc}")


SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Faults that are temporary and self-clearing. Anything NOT in this set is a
# configuration or permissions fault that will recur on every single event.
_TRANSIENT_DDB_ERRORS = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServerError",
    "ServiceUnavailable",
    "TransactionConflictException",
}


def _block_ip(ip: str, features: dict, result: dict):
    """
    Atomically claim the block for this IP. Returns (blocked_now, prior_severity).

    The old flow read the blocklist first and decided afterwards — two
    concurrent invocations (a burst of attack requests fans out across
    Lambdas) both read "not blocked", both fell through, and both sent a
    Telegram message. The decision now lives INSIDE DynamoDB as a conditional
    write, which is atomic: exactly one writer wins per severity level.

      - IP not blocked                          -> write succeeds, notify once
      - blocked at LOWER severity (escalation)  -> write succeeds, notify once,
                                                   prior severity returned so the
                                                   message can say "escalated"
      - blocked at same/higher severity (dup)   -> ConditionalCheckFailed, silent

      - block TTL already expired                -> write succeeds, notify once
                                                   (a lapsed block must be
                                                   re-armed, and DynamoDB's TTL
                                                   sweeper can lag by up to 48h)

    Condition expressions accept only attribute_exists, attribute_not_exists,
    attribute_type, begins_with, contains and size. if_not_exists() is an
    UPDATE-expression function and is rejected here with a ValidationException,
    so the "treat a missing rank as 0" case is expressed as an explicit
    attribute_not_exists(severity_rank) clause instead.

    `ttl` is a DynamoDB reserved word, so it is referenced via the #ttl alias.
    """
    severity    = result.get("severity", "MEDIUM")
    rank        = SEVERITY_RANK.get(severity, 2)
    ttl_seconds = TTL_BY_SEVERITY.get(severity, 3600)
    now_epoch   = int(time.time())
    ttl_epoch   = now_epoch + ttl_seconds

    try:
        resp = dynamo.put_item(
            TableName=BLOCKLIST_TABLE,
            Item={
                "ip":            {"S": ip},
                "blocked_at":    {"S": datetime.now(timezone.utc).isoformat()},
                "reason":        {"S": result.get("reason", "ML anomaly")},
                "score":         {"N": str(result.get("score", 0))},
                "source":        {"S": "acs-auto-block"},
                "geo_anomaly":   {"N": str(features.get("geo_anomaly", 0))},
                "severity":      {"S": severity},
                "severity_rank": {"N": str(rank)},
                "ttl":           {"N": str(ttl_epoch)},
            },
            ConditionExpression=(
                "attribute_not_exists(ip) "
                "OR attribute_not_exists(severity_rank) "
                "OR severity_rank < :rank "
                "OR #ttl < :now"
            ),
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":rank": {"N": str(rank)},
                ":now":  {"N": str(now_epoch)},
            },
            ReturnValues="ALL_OLD",
        )
        old   = resp.get("Attributes") or {}
        prior = old.get("severity", {}).get("S") if old else None
        if WAF_IPSET_ID:
            _add_ip_to_waf_set(ip)
        return True, prior

    except dynamo.exceptions.ConditionalCheckFailedException:
        # Already blocked at equal or higher severity, and still within TTL.
        # This is the duplicate path: stay silent. The WAF entry already exists
        # (idempotent add on the invocation that won the write).
        return False, None

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in _TRANSIENT_DDB_ERRORS:
            # Throttle or a brief service fault: rare and self-clearing, so
            # failing open cannot storm. Enforce at the WAF and let the caller
            # notify — a repeated message beats a silent miss.
            print(f"[WARN] Transient DynamoDB fault on blocklist write ({code}) — alerting anyway.")
            if WAF_IPSET_ID:
                _add_ip_to_waf_set(ip)
            return True, None
        # Permanent fault (ValidationException, AccessDeniedException,
        # ResourceNotFoundException). These fail identically for EVERY event,
        # so failing open here emits one alert and one Telegram message per
        # request. Fail closed and make the fault loud in CloudWatch instead:
        # an empty blocklist is an honest signal that enforcement is broken,
        # whereas an alert storm hides it.
        print(f"[ERROR] Blocklist write REJECTED ({code}) for {ip}: {exc}")
        print("[ERROR] Block not recorded and no alert raised — this is a configuration fault, not traffic.")
        return False, None

    except Exception as exc:
        print(f"[ERROR] Unexpected blocklist failure for {ip}: {exc}")
        return False, None


def _add_ip_to_waf_set(ip: str, max_retries: int = 5):
    """
    Add /32 CIDR of the IP to the WAF IP Set.

    Concurrent invocations (e.g. a burst of attack requests) may each try to
    update the same IP Set at once. WAF uses optimistic locking via a LockToken,
    so simultaneous writers collide with WAFOptimisticLockException. We retry
    with a fresh token and a short backoff; the operation is idempotent (adding
    an IP already present is a no-op), so retrying is safe.
    """
    import random
    for attempt in range(max_retries):
        try:
            resp = wafv2.get_ip_set(Name=WAF_IPSET_NAME, Scope=WAF_IPSET_SCOPE, Id=WAF_IPSET_ID)
            addresses = set(resp["IPSet"]["Addresses"])
            cidr = f"{ip}/32"
            if cidr in addresses:
                return  # already blocked — nothing to do (idempotent)
            addresses.add(cidr)
            wafv2.update_ip_set(
                Name=WAF_IPSET_NAME,
                Scope=WAF_IPSET_SCOPE,
                Id=WAF_IPSET_ID,
                Addresses=list(addresses),
                LockToken=resp["LockToken"],
            )
            return  # success
        except wafv2.exceptions.WAFOptimisticLockException:
            # Another invocation updated the set first; back off and retry.
            time.sleep(0.2 * (attempt + 1) + random.uniform(0, 0.2))
            continue
        except Exception as exc:
            print(f"[WARN] WAF IP Set update failed: {exc}")
            return
    print(f"[WARN] WAF IP Set update gave up after {max_retries} retries for {ip}")


def _send_telegram(ip: str, features: dict, result: dict, escalated_from: str = None):
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        print(f"[TELEGRAM DISABLED] Would alert on {ip}: {result.get('reason')}")
        return

    severity = result.get("severity", "MEDIUM")
    threat   = _classify_threat(features, severity)
    emoji    = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F7E2"}.get(severity, "\u26AA")
    ttl_h    = TTL_BY_SEVERITY.get(severity, 3600) // 3600

    header = "ACS Sentinel Alert"
    if escalated_from:
        header = f"ACS Sentinel Alert \u2B06 escalated from {escalated_from}"

    msg = (
        f"{header}\n"
        f"{emoji} Severity : {severity}\n"
        f"Threat    : {threat}\n"
        f"IP Blocked: {ip}\n"
        f"Score     : {result.get('score', 'n/a')}\n"
        f"Reason    : {result.get('reason', '')}\n"
        f"Expires   : {ttl_h}h\n"
    )
    reply_markup = {"inline_keyboard": [[{"text": f"Unblock {ip}", "callback_data": f"unblock:{ip}"}]]}
    try:
        url    = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        params = {"chat_id": TELEGRAM_CHAT_ID, "text": msg, "reply_markup": json.dumps(reply_markup)}
        data   = urllib.parse.urlencode(params).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=2)
    except Exception as exc:
        print(f"[WARN] Telegram send failed: {exc}")


def _process_events(log_events, engine) -> int:
    processed = 0
    for log_event in log_events:
        ip = log_event.get("ip", "")
        if not ip or ip in ("127.0.0.1", "::1"):
            continue

        features = extract_features(ip, log_event)
        result   = engine.score(features)
        processed += 1

        log_id = f"{int(time.time() * 1000)}-{ip.replace('.', '-')}"
        level  = result.get("severity", "INFO") if result["is_anomaly"] else "INFO"
        try:
            dynamo.put_item(
                TableName=LOGSTREAM_TABLE,
                Item={
                    "log_id":      {"S": log_id},
                    # Constant partition key for the "by-time" GSI: lets the
                    # dashboard Query newest-first instead of Scanning the whole
                    # table on every poll (correct ordering AND ~free reads).
                    "gsi_pk":      {"S": "LOG"},
                    "timestamp":   {"S": datetime.now(timezone.utc).isoformat()},
                    "level":       {"S": level},
                    "source":      {"S": "acs-sentinel"},
                    "message":     {"S": f"{log_event.get('event_type', 'EVENT')} | score: {result.get('score', 0)}"},
                    "source_ip":   {"S": ip},
                    "geo_anomaly": {"N": str(features["geo_anomaly"])},
                    "score":       {"N": str(round(result.get("score", 0), 4))},
                },
            )
        except Exception as exc:
            print(f"[ERROR] Failed to write log entry: {exc}")

        if result["is_anomaly"]:
            # The blocklist write IS the dedup gate (see _block_ip). Alert and
            # notification only fire for the invocation that won the write, so
            # one case = one Telegram message, however many concurrent Lambdas
            # the burst fanned out to. Escalations win again by design.
            blocked_now, prior_sev = _block_ip(ip, features, result)
            if not blocked_now:
                continue  # duplicate of an active block — already alerted
            _write_alert(ip, features, result)
            _send_telegram(ip, features, result, escalated_from=prior_sev)

    return processed


def handler(event, context):
    engine = _get_engine()
    processed = 0

    # Case 1: Direct CloudWatch Logs subscription -> {"awslogs": {"data": ...}}
    if "awslogs" in event:
        try:
            log_events = _decode_cwlogs_direct(event)
            processed += _process_events(log_events, engine)
        except Exception as exc:
            print(f"[ERROR] Could not decode CloudWatch Logs event: {exc}")
        return {"statusCode": 200, "processed": processed}

    # Case 2: Kinesis-triggered -> {"Records": [{"kinesis": {...}}, ...]}
    for record in event.get("Records", []):
        try:
            log_events = _decode_kinesis_record(record)
        except Exception as exc:
            print(f"[ERROR] Could not decode Kinesis record: {exc}")
            continue
        processed += _process_events(log_events, engine)

    return {"statusCode": 200, "processed": processed}
