"""
lambda_function.py — ACS Sentinel TARGET Application

This is the "victim" app the security system protects. It is a real,
browser-viewable web page (a fake SME business portal with a login form)
served entirely from Lambda + API Gateway. No EC2, no VPC.

Why it exists:
  - Gives a real HTTPS URL you can open in a browser and interact with.
  - Every request is logged as a structured JSON line to CloudWatch, which
    the detection pipeline (CloudWatch -> Kinesis -> Detection Lambda)
    consumes to score anomalies.
  - Can be attacked (brute-force login, request floods) for the WAF
    blocking demo. WAF attaches directly to this app's API Gateway.

Routes:
  GET  /            -> renders the SME portal login page (HTML)
  POST /login       -> processes a login attempt (always fails unless the
                       demo creds are used); logs the attempt
  GET  /health      -> plain health check
  GET  /dashboard   -> a fake "logged in" page (only reachable with demo creds)

Logging format (one JSON object per request, picked up by the pipeline):
  {"ip": "1.2.3.4", "event_type": "LOGIN_FAIL", "status": 401,
   "path": "/login", "payload_size": 42, "user_agent": "...",
   "timestamp": "..."}
"""

import json
import time
import base64
from datetime import datetime, timezone

# Demo credentials for the "successful login" path during a demo.
DEMO_USER = "smeadmin"
DEMO_PASS = "portal2026"


def _client_ip(event) -> str:
    # HTTP API (v2): requestContext.http.sourceIp
    # REST API (v1): requestContext.identity.sourceIp
    rc = event.get("requestContext", {})
    try:
        ip = rc.get("http", {}).get("sourceIp")
        if ip:
            return ip
    except (AttributeError, TypeError):
        pass
    try:
        ip = rc.get("identity", {}).get("sourceIp")
        if ip:
            return ip
    except (AttributeError, TypeError):
        pass
    headers = event.get("headers") or {}
    xff = headers.get("x-forwarded-for", "") or headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else "0.0.0.0"


def _log_event(event_type: str, ip: str, status: int, path: str, payload_size: int, user_agent: str):
    """
    Emit a single structured JSON line. print() in Lambda goes straight to
    CloudWatch Logs, which the subscription filter forwards to Kinesis.
    """
    record = {
        "ip":           ip,
        "event_type":   event_type,
        "status":       status,
        "path":         path,
        "payload_size": payload_size,
        "user_agent":   user_agent,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(record))


def _html_response(html: str, status: int = 200):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": html,
    }


def _login_page(error: str = "") -> str:
    error_html = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bumi SME Portal — Secure Login</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: linear-gradient(135deg, #1e3a5f 0%, #0f1c2e 100%);
      min-height: 100vh; display: flex; align-items: center;
      justify-content: center; color: #e8eef5;
    }}
    .card {{
      background: rgba(255,255,255,0.06); backdrop-filter: blur(12px);
      border: 1px solid rgba(255,255,255,0.12); border-radius: 14px;
      padding: 40px; width: 100%; max-width: 380px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.4);
    }}
    .logo {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; color: #4db8ff; }}
    .sub  {{ font-size: 13px; color: #8ba3bd; margin-bottom: 28px; }}
    label {{ display: block; font-size: 12px; color: #a9bdd4; margin: 14px 0 6px; }}
    input {{
      width: 100%; padding: 11px 14px; border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.15); background: rgba(0,0,0,0.25);
      color: #fff; font-size: 14px;
    }}
    button {{
      width: 100%; margin-top: 24px; padding: 12px; border: none;
      border-radius: 8px; background: #2b7fff; color: #fff; font-size: 15px;
      font-weight: 600; cursor: pointer;
    }}
    button:hover {{ background: #1a6fef; }}
    .err {{ color: #ff6b81; font-size: 13px; margin-top: 16px; text-align: center; }}
    .foot {{ margin-top: 22px; font-size: 11px; text-align: center; color:#5f7691; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Bumi SME Portal</div>
    <div class="sub">Business Banking &amp; Operations — Malaysia</div>
    <form method="POST" action="/login">
      <label>Username</label>
      <input name="username" autocomplete="off" placeholder="Enter username">
      <label>Password</label>
      <input name="password" type="password" placeholder="Enter password">
      <button type="submit">Sign In</button>
      {error_html}
    </form>
    <div class="foot">Protected by ACS Sentinel &middot; Unauthorized access is monitored</div>
  </div>
</body>
</html>"""


def _dashboard_page() -> str:
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Bumi SME Portal — Dashboard</title>
<style>
  body { font-family:'Segoe UI',system-ui,sans-serif; background:#0f1c2e; color:#e8eef5;
         padding:60px; text-align:center; }
  .box { max-width:520px; margin:0 auto; background:rgba(255,255,255,0.06);
         border:1px solid rgba(255,255,255,0.12); border-radius:14px; padding:40px; }
  h1 { color:#4db8ff; }
</style></head>
<body><div class="box">
  <h1>Welcome back, SME Admin</h1>
  <p style="margin-top:14px;color:#a9bdd4">Account balance: RM 148,250.00</p>
  <p style="margin-top:8px;color:#a9bdd4">3 pending transfers &middot; 12 invoices due</p>
</div></body></html>"""


def _parse_form(body: str) -> dict:
    out = {}
    if not body:
        return out
    for pair in body.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v.replace("+", " ")
    return out


def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path   = event.get("rawPath", "/")
    ip     = _client_ip(event)
    headers = event.get("headers") or {}
    ua     = headers.get("user-agent", "unknown")
    body   = event.get("body", "") or ""
    if event.get("isBase64Encoded") and body:
        try:
            body = base64.b64decode(body).decode("utf-8")
        except Exception:
            pass
    payload_size = len(body.encode("utf-8")) if body else 0

    if path == "/health":
        _log_event("HEALTH", ip, 200, path, 0, ua)
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"status": "ok", "app": "bumi-sme-portal"})}

    if path == "/login" and method == "POST":
        form = _parse_form(body)
        user = form.get("username", "")
        pw   = form.get("password", "")
        if user == DEMO_USER and pw == DEMO_PASS:
            _log_event("LOGIN_SUCCESS", ip, 200, path, payload_size, ua)
            return _html_response(_dashboard_page(), 200)
        else:
            _log_event("LOGIN_FAIL", ip, 401, path, payload_size, ua)
            return _html_response(_login_page("Invalid username or password"), 401)

    if path == "/dashboard":
        # Not really protected — for demo realism only; log the access.
        _log_event("PAGE_VIEW", ip, 200, path, 0, ua)
        return _html_response(_dashboard_page(), 200)

    # Default: the login page.
    _log_event("PAGE_VIEW", ip, 200, path, 0, ua)
    return _html_response(_login_page(), 200)
