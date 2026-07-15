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
    # For demo/testing, honour an explicit X-Forwarded-For header first so the
    # attack simulator can inject distinct source IPs per scenario (each IP gets
    # its own detection window, letting all severity tiers be demonstrated).
    headers = event.get("headers") or {}
    xff = headers.get("x-forwarded-for", "") or headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()

    # Otherwise use the real source IP.
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
    return "0.0.0.0"


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
    <form method="POST" action="login">
      <label>Username</label>
      <input name="username" autocomplete="off" placeholder="Enter username">
      <label>Password</label>
      <input name="password" type="password" placeholder="Enter password">
      <button type="submit">Sign In</button>
      {error_html}
    </form>
    <div class="foot">New business? <a href="register" style="color:#4db8ff">Register here</a><br>
      Protected by ACS Sentinel &middot; Unauthorized access is monitored</div>
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
  <p style="margin-top:20px"><a href="transactions" style="color:#4db8ff;margin:0 10px">Transactions</a>
     <a href="profile" style="color:#4db8ff;margin:0 10px">Profile</a></p>
</div></body></html>"""


def _page_shell(title: str, body: str) -> str:
    """Shared dark-themed shell for the inner pages, matching the portal style."""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bumi SME Portal — {title}</title>
<style>
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f1c2e; color:#e8eef5;
         padding:50px; }}
  .box {{ max-width:620px; margin:0 auto; background:rgba(255,255,255,0.06);
          border:1px solid rgba(255,255,255,0.12); border-radius:14px; padding:36px; }}
  h1 {{ color:#4db8ff; margin-bottom:18px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
  td, th {{ text-align:left; padding:9px 6px; border-bottom:1px solid rgba(255,255,255,0.08);
            font-size:14px; }}
  th {{ color:#8ba3bd; font-weight:600; }}
  .nav a {{ color:#4db8ff; margin-right:16px; font-size:13px; }}
  .field {{ margin:10px 0; color:#a9bdd4; font-size:14px; }}
  .field b {{ color:#e8eef5; }}
</style></head>
<body><div class="box">
  <div class="nav"><a href="dashboard">&larr; Dashboard</a><a href="transactions">Transactions</a><a href="profile">Profile</a></div>
  <h1>{title}</h1>
  {body}
</div></body></html>"""


def _transactions_page() -> str:
    rows = """
    <table>
      <tr><th>Date</th><th>Description</th><th>Amount (RM)</th></tr>
      <tr><td>2026-07-12</td><td>Supplier payment — Tan Trading</td><td>-4,820.00</td></tr>
      <tr><td>2026-07-11</td><td>Invoice settled — #INV-2043</td><td>+12,500.00</td></tr>
      <tr><td>2026-07-10</td><td>Payroll transfer</td><td>-18,240.00</td></tr>
      <tr><td>2026-07-09</td><td>POS settlement</td><td>+3,905.50</td></tr>
    </table>"""
    return _page_shell("Recent Transactions", rows)


def _profile_page() -> str:
    body = """
    <div class="field">Business name: <b>Bumi Maju Enterprise</b></div>
    <div class="field">Registration no: <b>SSM 20219847-K</b></div>
    <div class="field">Account holder: <b>SME Admin</b></div>
    <div class="field">Tier: <b>Business Banking — Standard</b></div>
    <div class="field">Contact: <b>admin@bumimaju.example</b></div>"""
    return _page_shell("Business Profile", body)


def _register_page(error: str = "") -> str:
    note = f'<p style="color:#ff6b81;font-size:13px;margin-top:14px">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bumi SME Portal — Register</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif;
          background:linear-gradient(135deg,#1e3a5f,#0f1c2e); min-height:100vh;
          display:flex; align-items:center; justify-content:center; color:#e8eef5; }}
  .card {{ background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12);
           border-radius:14px; padding:40px; width:100%; max-width:400px; }}
  .logo {{ font-size:22px; font-weight:700; color:#4db8ff; margin-bottom:4px; }}
  .sub {{ font-size:13px; color:#8ba3bd; margin-bottom:24px; }}
  label {{ display:block; font-size:12px; color:#a9bdd4; margin:12px 0 6px; }}
  input {{ width:100%; padding:11px 14px; border-radius:8px;
           border:1px solid rgba(255,255,255,0.15); background:rgba(0,0,0,0.25);
           color:#fff; font-size:14px; }}
  button {{ width:100%; margin-top:22px; padding:12px; border:none; border-radius:8px;
            background:#2b7fff; color:#fff; font-size:15px; font-weight:600; cursor:pointer; }}
  .foot {{ margin-top:20px; font-size:11px; text-align:center; color:#5f7691; }}
  a {{ color:#4db8ff; }}
</style></head>
<body><div class="card">
  <div class="logo">Bumi SME Portal</div>
  <div class="sub">Register your business account</div>
  <form method="POST" action="register">
    <label>Business name</label><input name="business" placeholder="Enter business name">
    <label>Email</label><input name="email" placeholder="Enter email">
    <label>Password</label><input name="password" type="password" placeholder="Create password">
    <button type="submit">Create Account</button>
    {note}
  </form>
  <div class="foot">Already registered? <a href="./">Sign in</a> &middot; Monitored by ACS Sentinel</div>
</div></body></html>"""


def _not_found_page() -> str:
    return _page_shell("404 — Not Found",
        '<p style="color:#a9bdd4">The page you requested does not exist on this portal.</p>')


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
    # Method: REST API (v1) uses event["httpMethod"]; HTTP API (v2) uses
    # requestContext.http.method. Check both.
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    )
    # Path: REST API (v1) uses event["path"]; HTTP API (v2) uses rawPath.
    path   = event.get("path") or event.get("rawPath") or "/"
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

    # REST API paths may arrive with the stage prefix (e.g. "/prod/login").
    # Normalise so route matching works the same on HTTP API and REST API.
    norm_path = path
    for stage in ("/prod", "/default", "/$default"):
        if norm_path.startswith(stage + "/") or norm_path == stage:
            norm_path = norm_path[len(stage):] or "/"
            break
    if not norm_path:
        norm_path = "/"

    if norm_path == "/health":
        _log_event("HEALTH", ip, 200, norm_path, 0, ua)
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"status": "ok", "app": "bumi-sme-portal"})}

    if norm_path == "/login" and method == "POST":
        form = _parse_form(body)
        user = form.get("username", "")
        pw   = form.get("password", "")
        if user == DEMO_USER and pw == DEMO_PASS:
            _log_event("LOGIN_SUCCESS", ip, 200, norm_path, payload_size, ua)
            return _html_response(_dashboard_page(), 200)
        else:
            _log_event("LOGIN_FAIL", ip, 401, norm_path, payload_size, ua)
            return _html_response(_login_page("Invalid username or password"), 401)

    # Registration endpoint — another public surface an attacker can hammer.
    if norm_path == "/register":
        if method == "POST":
            form = _parse_form(body)
            # Demo: registration is "closed", always rejects — but the attempt
            # is logged, so credential-stuffing here still feeds detection.
            _log_event("REGISTER_ATTEMPT", ip, 403, norm_path, payload_size, ua)
            return _html_response(
                _register_page("Registration is currently closed for new SMEs."), 403)
        _log_event("PAGE_VIEW", ip, 200, norm_path, 0, ua)
        return _html_response(_register_page(), 200)

    # Authenticated-looking inner pages (demo realism — not truly protected,
    # but they give the app more legitimate surface and varied page views).
    if norm_path in ("/dashboard", "/transactions", "/profile"):
        page = {
            "/dashboard":    _dashboard_page,
            "/transactions": _transactions_page,
            "/profile":      _profile_page,
        }[norm_path]
        _log_event("PAGE_VIEW", ip, 200, norm_path, 0, ua)
        return _html_response(page(), 200)

    # Home page.
    if norm_path in ("/", ""):
        _log_event("PAGE_VIEW", ip, 200, "/", 0, ua)
        return _html_response(_login_page(), 200)

    # Unknown path -> 404. This is what makes PATH SCANNING detectable: probing
    # for /admin, /.env, /wp-login.php, /backup.sql etc. now returns 404s, which
    # raise the failed_status_rate and trip the "Scan Probe" detection — exactly
    # as a real web server would behave.
    _log_event("NOT_FOUND", ip, 404, norm_path, 0, ua)
    return _html_response(_not_found_page(), 404)
