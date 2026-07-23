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
# Second enforcement point for the agentless edge path. CLOUDFRONT-scope
# resources are only addressable via us-east-1, whatever region this runs in.
WAF_IPSET_ID_CF   = os.environ.get("WAF_IPSET_ID_CF", "")
WAF_IPSET_NAME_CF = os.environ.get("WAF_IPSET_NAME_CF", "acs-blocked-ips-cf")

# User management (admin-only). The allowlist table is the same one the
# PreSignUp trigger reads; role changes are enforced through Cognito group
# membership, which is what actually lands in the JWT and gates these routes.
USER_POOL_ID    = os.environ.get("COGNITO_USER_POOL_ID", "ap-southeast-1_D8EGJnIiP")
ALLOWLIST_TABLE = os.environ.get("ALLOWLIST_TABLE", "allowed-users")
ADMIN_GROUP     = "admin"

TELEGRAM_TOKEN          = os.environ.get("TELEGRAM_BOT_TOKEN", "")
# Random string you choose at setWebhook time. Telegram echoes it back in the
# X-Telegram-Bot-Api-Secret-Token header on every webhook call; anything that
# arrives without it is not Telegram and gets a 403.
TELEGRAM_WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")

GSI_PK = "LOG"                # constant partition key of the by-time index
POLL_LIMIT_DEFAULT = 300      # newest rows returned to the 4s poll
PAGE_LIMIT_MAX     = 500      # hard cap per request
SEARCH_QUERY_PAGES = 8        # DynamoDB pages walked per search request

dynamo  = boto3.client("dynamodb", region_name=AWS_REGION)
wafv2   = boto3.client("wafv2", region_name=AWS_REGION)
wafv2_cf = boto3.client("wafv2", region_name="us-east-1")
cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

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


def _query_logs_page(limit, cursor, q, since=None, until=None):
    """Time-ordered page via the by-time GSI. Raises if the index is missing.

    `since`/`until` (ISO-8601 strings) bound the sort key so the GSI reads ONLY
    rows in that window — the cheap way to answer "show me the last few days"
    instead of paging back through everything. ISO timestamps sort
    lexicographically, so a string BETWEEN is a correct time range."""
    needle = (q or "").strip().lower()
    lek    = _decode_cursor(cursor)
    items: list = []
    scanned = 0

    # Sort-key range on the GSI's `timestamp` range key. Aliased via
    # ExpressionAttributeNames because `timestamp` is a DynamoDB reserved word.
    key_expr = "gsi_pk = :p"
    values   = {":p": {"S": GSI_PK}}
    names    = None
    if since and until:
        key_expr += " AND #ts BETWEEN :from AND :to"
        values[":from"] = {"S": since}; values[":to"] = {"S": until}
        names = {"#ts": "timestamp"}
    elif since:
        key_expr += " AND #ts >= :from"
        values[":from"] = {"S": since}; names = {"#ts": "timestamp"}
    elif until:
        key_expr += " AND #ts <= :to"
        values[":to"] = {"S": until}; names = {"#ts": "timestamp"}

    # Plain paging reads exactly one page sized to the limit. A search walks
    # up to SEARCH_QUERY_PAGES pages per request so one Lambda call does a
    # bounded amount of work; the returned cursor lets the client continue.
    pages      = SEARCH_QUERY_PAGES if needle else 1
    page_limit = 400 if needle else limit

    for _ in range(pages):
        kwargs = {
            "TableName":                 LOGSTREAM_TABLE,
            "IndexName":                 LOGS_GSI,
            "KeyConditionExpression":    key_expr,
            "ExpressionAttributeValues": values,
            "ScanIndexForward":          False,   # newest first
            "Limit":                     page_limit,
        }
        if names:
            kwargs["ExpressionAttributeNames"] = names
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


def _scan_logs_page(limit, cursor, q, since=None, until=None):
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
    if since:
        items = [e for e in items if e["timestamp"] >= since]
    if until:
        items = [e for e in items if e["timestamp"] <= until]
    items.sort(key=lambda x: x["timestamp"], reverse=True)
    return items, _encode_cursor(resp.get("LastEvaluatedKey")), scanned


def _get_logs_page(limit, cursor, q, since=None, until=None):
    limit = max(1, min(limit, PAGE_LIMIT_MAX))
    try:
        return _query_logs_page(limit, cursor, q, since, until)
    except Exception as exc:
        # Most likely: GSI not created yet (ValidationException). Fall back
        # rather than blank the dashboard, and say so in the logs.
        print(f"[WARN] by-time GSI query failed ({exc}) — falling back to Scan")
        return _scan_logs_page(limit, cursor, q, since, until)


# ── Unblock (shared by dashboard DELETE and Telegram button) ─────────────────

def _remove_from_one_set(client, name: str, scope: str, ipset_id: str, ip: str) -> bool:
    try:
        resp = client.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
        addresses = [a for a in resp["IPSet"]["Addresses"] if a != f"{ip}/32"]
        client.update_ip_set(
            Name=name, Scope=scope, Id=ipset_id,
            Addresses=addresses, LockToken=resp["LockToken"],
        )
        return True
    except Exception as exc:
        print(f"[WARN] WAF removal failed ({scope}/{name}): {exc}")
        return False


def _remove_from_waf(ip: str):
    """
    Lift the block at every enforcement point.

    An unblock that clears only one set is worse than no unblock at all: the
    operator is told the address is released, the dashboard shows it released,
    and the visitor still gets a 403 from whichever edge was missed. Both sets
    are therefore attempted independently, and each outcome is logged.
    """
    targets = []
    if WAF_IPSET_ID:
        targets.append((wafv2, WAF_IPSET_NAME, WAF_IPSET_SCOPE, WAF_IPSET_ID))
    if WAF_IPSET_ID_CF:
        targets.append((wafv2_cf, WAF_IPSET_NAME_CF, "CLOUDFRONT", WAF_IPSET_ID_CF))

    for client, name, scope, ipset_id in targets:
        ok = _remove_from_one_set(client, name, scope, ipset_id, ip)
        print(f"[WAF] unblock {ip} -> {scope}/{name}: {'ok' if ok else 'FAILED'}")


def _unblock_ip(ip: str, actor: str = "dashboard") -> bool:
    """Unblock an IP. Idempotent, and always removes the block.

    The delete runs UNCONDITIONALLY — deleting an absent row is a harmless no-op
    that still succeeds — so the block is guaranteed to be gone and the dashboard
    always reflects it. ReturnValues=ALL_OLD then tells us whether a row was
    actually there: only a real removal cleans WAF and writes an audit row. An IP
    that escalates medium -> high -> critical has three Telegram alerts but one
    blocklist row, so the first tap records the unblock and the rest report
    'already unblocked' without duplicating the audit trail.

    (Earlier this used a conditional delete keyed on attribute_exists(ip); if the
    condition ever failed for a live block the whole unblock silently no-op'd —
    the IP stayed blocked and nothing was recorded. ReturnValues avoids that.)
    """
    try:
        resp = dynamo.delete_item(
            TableName=BLOCKLIST_TABLE,
            Key={"ip": {"S": ip}},
            ReturnValues="ALL_OLD",
        )
        existed = "Attributes" in resp
    except Exception as exc:
        print(f"[ERROR] DynamoDB delete failed: {exc}")
        existed = True   # unknown state — treat as real so WAF is cleaned and recorded

    if not existed:
        return False     # was already unblocked — no WAF churn, no duplicate audit

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
    return True


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
        did = _unblock_ip(ip, actor="telegram")

        # Feedback in the chat itself, or the button looks dead even when it
        # worked: pop a toast on the tapper's screen, then rewrite the alert
        # message so the button disappears and the outcome is recorded inline.
        # A second/third escalation alert for the same IP is now a no-op — it
        # reports "already unblocked" instead of logging another unblock.
        _telegram_api("answerCallbackQuery", {
            "callback_query_id": callback["id"],
            "text": f"Unblocked {ip}" if did else f"{ip} was already unblocked",
        })
        msg = callback.get("message") or {}
        chat_id    = (msg.get("chat") or {}).get("id")
        message_id = msg.get("message_id")
        if chat_id and message_id:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            note  = "Unblocked" if did else "Already unblocked"
            _telegram_api("editMessageText", {
                "chat_id":    chat_id,
                "message_id": message_id,
                "text":       f"{msg.get('text', '')}\n\n\u2705 {note} via Telegram at {stamp}",
            })

    # Always 200: Telegram retries non-200 responses, which would replay the
    # same callback and re-trigger the unblock path.
    return _response(200, {"ok": True})


# ── User management (admin-only) ─────────────────────────────────────────────
#
# Authorisation boundary. The frontend hides the Users tab from non-admins, but
# that is cosmetic: a valid operator token can still call this endpoint. Every
# action below therefore re-checks cognito:groups from the API Gateway JWT
# authoriser and refuses anything that is not an admin. This is the real gate.

def _json_body(event) -> dict:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode()
        except Exception:
            raw = "{}"
    try:
        return json.loads(raw) or {}
    except json.JSONDecodeError:
        return {}


def _claims(event) -> dict:
    return ((((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {})


def _groups(event) -> set:
    # HTTP API (payload 2.0) serialises the cognito:groups array claim as a
    # bracketed, space-separated string, e.g. "[admin operator]". Accept both
    # that and a genuine list so the check is not brittle across API versions.
    raw = _claims(event).get("cognito:groups", "")
    if isinstance(raw, list):
        return {g for g in raw if g}
    return {g for g in raw.strip("[]").replace(",", " ").split() if g}


def _is_admin(event) -> bool:
    return ADMIN_GROUP in _groups(event)


def _caller_email(event) -> str:
    return (_claims(event).get("email") or "").strip().lower()


def _audit_log(message: str):
    """Write an AUDIT row to log-stream so admin actions are accountable. These
    surface in the log stream alongside traffic and unblock events."""
    try:
        dynamo.put_item(
            TableName=LOGSTREAM_TABLE,
            Item={
                "log_id":      {"S": f"{int(time.time() * 1000)}-admin"},
                "gsi_pk":      {"S": GSI_PK},
                "timestamp":   {"S": datetime.now(timezone.utc).isoformat()},
                "level":       {"S": "AUDIT"},
                "source":      {"S": "acs-dashboard"},
                "message":     {"S": message},
                "source_ip":   {"S": ""},
                "geo_anomaly": {"N": "0"},
            },
        )
    except Exception as exc:
        print(f"[WARN] audit write failed: {exc}")


def _valid_email(email: str) -> bool:
    if email.startswith("@"):                 # whole-domain allow entry
        return "." in email[1:] and " " not in email
    return "@" in email and "." in email.split("@", 1)[1] and " " not in email


def _usernames_for_email(email: str) -> list:
    """Every Cognito username sharing this email — typically a password user
    and/or a federated Google_ user."""
    out, token = [], None
    for _ in range(5):
        kwargs = {"UserPoolId": USER_POOL_ID, "Filter": f'email = "{email}"', "Limit": 60}
        if token:
            kwargs["PaginationToken"] = token
        resp = cognito.list_users(**kwargs)
        out.extend(u["Username"] for u in resp.get("Users", []))
        token = resp.get("PaginationToken")
        if not token:
            break
    return out


def _admin_usernames() -> set:
    out, token = set(), None
    for _ in range(5):
        kwargs = {"UserPoolId": USER_POOL_ID, "GroupName": ADMIN_GROUP, "Limit": 60}
        if token:
            kwargs["NextToken"] = token
        resp = cognito.list_users_in_group(**kwargs)
        out.update(u["Username"] for u in resp.get("Users", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _list_users() -> dict:
    # Allowlist rows (who MAY enter) keyed by email.
    allow = {}
    scan_kwargs = {"TableName": ALLOWLIST_TABLE}
    while True:
        resp = dynamo.scan(**scan_kwargs)
        for i in resp.get("Items", []):
            e = i.get("email", {}).get("S", "")
            allow[e] = {
                "role":     i.get("role", {}).get("S", "operator"),
                "added_by": i.get("added_by", {}).get("S", ""),
                "added_at": i.get("added_at", {}).get("S", ""),
            }
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek

    admins = _admin_usernames()

    # Cognito accounts (who HAS entered), grouped by email.
    accounts_by_email, token = {}, None
    for _ in range(10):
        kwargs = {"UserPoolId": USER_POOL_ID, "Limit": 60}
        if token:
            kwargs["PaginationToken"] = token
        resp = cognito.list_users(**kwargs)
        for u in resp.get("Users", []):
            uname = u["Username"]
            attrs = {a["Name"]: a["Value"] for a in u.get("Attributes", [])}
            e = (attrs.get("email") or "").strip().lower()
            accounts_by_email.setdefault(e, []).append({
                "username":  uname,
                "federated": uname.startswith("Google_"),
                "status":    u.get("UserStatus", ""),
                "is_admin":  uname in admins,
            })
        token = resp.get("PaginationToken")
        if not token:
            break

    users, domains = [], []
    for email in sorted(set(allow) | set(accounts_by_email)):
        if email.startswith("@"):
            domains.append({"domain": email, "added_by": allow.get(email, {}).get("added_by", "")})
            continue
        accts = accounts_by_email.get(email, [])
        joined = len(accts) > 0
        actual = "admin" if any(a["is_admin"] for a in accts) else ("operator" if joined else "—")
        users.append({
            "email":         email,
            "invited":       email in allow,
            "intended_role": allow.get(email, {}).get("role", ""),
            "joined":        joined,
            "role":          actual,
            "accounts":      accts,
            "added_by":      allow.get(email, {}).get("added_by", ""),
            "added_at":      allow.get(email, {}).get("added_at", ""),
        })
    return {"users": users, "domains": domains}


def _invite_user(email: str, role: str, actor: str) -> dict:
    email = email.strip().lower()
    if not _valid_email(email):
        return _response(400, {"error": "invalid email or domain"})
    if email.startswith("@"):
        role = "domain"
    elif role not in ("admin", "operator"):
        role = "operator"
    dynamo.put_item(
        TableName=ALLOWLIST_TABLE,
        Item={
            "email":    {"S": email},
            "role":     {"S": role},
            "added_by": {"S": actor or "admin"},
            "added_at": {"S": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
        },
    )
    _audit_log(f"USER invited {email} as {role} by {actor or 'admin'}")
    return _response(200, {"status": "invited", "email": email, "role": role})


def _remove_user(email: str, actor: str) -> dict:
    email = email.strip().lower()
    if email == actor:
        return _response(400, {"error": "you cannot remove your own account"})
    # Remove from the allowlist so they cannot sign back in…
    dynamo.delete_item(TableName=ALLOWLIST_TABLE, Key={"email": {"S": email}})
    # …and delete any existing pool accounts so an active session is revoked.
    removed = []
    for uname in _usernames_for_email(email):
        try:
            cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=uname)
            removed.append(uname)
        except Exception as exc:
            print(f"[WARN] admin_delete_user failed for {uname}: {exc}")
    _audit_log(f"USER removed {email} by {actor} (accounts: {', '.join(removed) or 'none'})")
    return _response(200, {"status": "removed", "email": email, "accounts_deleted": removed})


def _set_role(email: str, role: str, actor: str) -> dict:
    email = email.strip().lower()
    if role not in ("admin", "operator"):
        return _response(400, {"error": "role must be admin or operator"})
    if email == actor and role != "admin":
        return _response(400, {"error": "you cannot remove your own admin access"})

    usernames = _usernames_for_email(email)
    for uname in usernames:
        try:
            if role == "admin":
                cognito.admin_add_user_to_group(UserPoolId=USER_POOL_ID, GroupName=ADMIN_GROUP, Username=uname)
            else:
                cognito.admin_remove_user_from_group(UserPoolId=USER_POOL_ID, GroupName=ADMIN_GROUP, Username=uname)
        except Exception as exc:
            print(f"[WARN] group change failed for {uname}: {exc}")

    # Keep the allowlist row's intended role in sync for display. Only touch the
    # role attribute so added_by / added_at survive.
    try:
        dynamo.update_item(
            TableName=ALLOWLIST_TABLE,
            Key={"email": {"S": email}},
            UpdateExpression="SET #r = :r",
            ExpressionAttributeNames={"#r": "role"},
            ExpressionAttributeValues={":r": {"S": role}},
        )
    except Exception as exc:
        print(f"[WARN] allowlist role sync failed for {email}: {exc}")

    # A group change only lands in a NEW token, so the affected user must sign
    # out and back in before the dashboard treats them as their new role.
    _audit_log(f"ROLE {email} set to {role} by {actor}")
    return _response(200, {
        "status": "role-updated", "email": email, "role": role,
        "applied_to": usernames,
        "note": "user must re-login for the change to take effect" if usernames
                else "no active account yet — applies on first login is NOT automatic; ask them to sign in, then set role again",
    })


def _handle_users(event) -> dict:
    if not _is_admin(event):
        return _response(403, {"error": "administrator access required"})
    body   = _json_body(event)
    action = (body.get("action") or "").lower()
    actor  = _caller_email(event)

    if action == "list":
        return _response(200, _list_users())
    if action == "invite":
        return _invite_user(body.get("email", ""), body.get("role", "operator"), actor)
    if action == "remove":
        return _remove_user(body.get("email", ""), actor)
    if action == "setrole":
        return _set_role(body.get("email", ""), body.get("role", ""), actor)
    return _response(400, {"error": "unknown action"})


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
            did = _unblock_ip(ip, actor=_caller_email(event) or "dashboard")
            return _response(200, {"status": "unblocked" if did else "already-unblocked", "ip": ip})

        if path == "/logs" and method == "GET":
            qsp    = event.get("queryStringParameters") or {}
            try:
                limit = int(qsp.get("limit", POLL_LIMIT_DEFAULT))
            except (TypeError, ValueError):
                limit = POLL_LIMIT_DEFAULT
            items, cursor, scanned = _get_logs_page(
                limit, qsp.get("cursor"), qsp.get("q"),
                since=qsp.get("from"), until=qsp.get("to"),
            )
            return _response(200, {"items": items, "cursor": cursor, "scanned": scanned})

        if path == "/users" and method == "POST":
            return _handle_users(event)

        if path == "/telegram/webhook" and method == "POST":
            return _handle_telegram_webhook(event)

        if path == "/health":
            return _response(200, {"status": "ok", "service": "acs-sentinel-dashboard"})

        return _response(404, {"error": "not found"})

    except Exception as exc:
        print(f"[ERROR] {exc}")
        return _response(500, {"error": str(exc)})
