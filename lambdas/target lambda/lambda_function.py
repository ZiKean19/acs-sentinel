"""
lambda_function.py — ACS Sentinel TARGET Application

The "victim" app the security system protects: a real, browser-viewable web
page (a small online shop's seller back-office with a login form) served
entirely from Lambda + API Gateway. No EC2, no VPC.

Why it exists:
  - Gives a real HTTPS URL you can open in a browser and interact with.
  - Every request is logged as a structured JSON line to CloudWatch, which the
    detection pipeline consumes to score anomalies.
  - The login/register endpoints are the attack surface for the brute-force /
    scan-probe demo. WAF attaches directly to this app's API Gateway.

The target is modelled as a small Malaysian online shop ("Warung Maju") rather
than a bank: banks run their own SOC and buy enterprise security, whereas a
resource-constrained SME shop is exactly the user ACS Sentinel is for — no
security team, yet a real target for credential stuffing.

Routes:
  GET  /            -> shop seller login page (attack surface)
  POST /login       -> processes a login attempt (fails unless demo creds)
  GET  /register    -> register page (POST always rejected, still logged)
  GET  /health      -> plain health check
  GET  /dashboard   -> seller back-office landing (post-login realism)
  GET  /orders      -> orders list
  GET  /products    -> products list
  GET  /sales       -> sales overview

Logging format (one JSON object per request, picked up by the pipeline):
  {"ip": "1.2.3.4", "event_type": "LOGIN_FAIL", "status": 401,
   "path": "/login", "payload_size": 42, "user_agent": "...", "timestamp": "..."}
"""

import json
import base64
from datetime import datetime, timezone

# Demo credentials for the "successful login" path during a demo.
DEMO_USER = "smeadmin"
DEMO_PASS = "portal2026"


def _client_ip(event) -> str:
    # Honour X-Forwarded-For first so the attack simulator can inject distinct
    # source IPs per scenario (each IP gets its own detection window).
    headers = event.get("headers") or {}
    xff = headers.get("x-forwarded-for", "") or headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
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
    """Emit one structured JSON line. print() in Lambda goes to CloudWatch Logs,
    which the subscription filter forwards to the detection pipeline."""
    print(json.dumps({
        "ip":           ip,
        "event_type":   event_type,
        "status":       status,
        "path":         path,
        "payload_size": payload_size,
        "user_agent":   user_agent,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }))


def _html_response(html: str, status: int = 200):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": html,
    }


# ── Shared presentation ──────────────────────────────────────────────────────

STYLE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#f4f1ea;color:#201e1a;min-height:100vh}
a{text-decoration:none;color:#b06a06}
.topbar{background:#fff;border-bottom:1px solid #e7e3da;padding:12px 22px;display:flex;align-items:center;gap:12px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:16px}
.mark{width:30px;height:30px;border-radius:8px;background:#b06a06;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700}
.nav{display:flex;gap:16px;margin-left:22px;font-size:14px}
.nav a{color:#6f6b63}
.nav a:hover{color:#b06a06}
.spacer{flex:1}
.owner{font-size:13px;color:#6f6b63}
.logout{font-size:13px;color:#b3261e}
.wrap{max-width:840px;margin:26px auto;padding:0 18px}
.h{font-size:13px;color:#6f6b63;margin:0 0 10px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.stat{background:#fff;border:1px solid #e7e3da;border-radius:10px;padding:14px}
.stat .lbl{font-size:12px;color:#6f6b63}
.stat .val{font-size:24px;font-weight:600;margin-top:4px}
.warn{color:#b06a06}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px}
.panel{background:#fff;border:1px solid #e7e3da;border-radius:12px;overflow:hidden}
.panel .ph{padding:12px 14px;border-bottom:1px solid #e7e3da;font-size:13px;color:#6f6b63;font-weight:600}
.row{display:flex;justify-content:space-between;padding:11px 14px;border-bottom:1px solid #e7e3da;font-size:14px}
.row:last-child{border-bottom:none}
.muted{color:#6f6b63}
.low{color:#b3261e}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e7e3da;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid #e7e3da;font-size:14px}
th{color:#6f6b63;font-weight:600;font-size:12px}
tr:last-child td{border-bottom:none}
.authwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth{background:#fff;border:1px solid #e7e3da;border-radius:16px;padding:34px;width:100%;max-width:380px;box-shadow:0 10px 40px rgba(60,40,0,.06)}
.auth .mark{width:48px;height:48px;border-radius:12px;font-size:22px;margin:0 auto 14px}
.auth h1{font-size:20px;text-align:center;font-weight:600}
.auth .sub{font-size:13px;color:#6f6b63;text-align:center;margin:4px 0 20px}
label{display:block;font-size:12px;color:#6f6b63;margin:14px 0 6px}
input{width:100%;padding:11px 13px;border-radius:9px;border:1px solid #e7e3da;background:#fff;color:#201e1a;font-size:14px}
input:focus{outline:none;border-color:#b06a06}
button{width:100%;margin-top:22px;padding:12px;border:none;border-radius:9px;background:#b06a06;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.06)}
.err{color:#b3261e;font-size:13px;margin-top:14px;text-align:center}
.foot{margin-top:20px;font-size:11px;text-align:center;color:#98938a}
"""


def _topbar(active: str = "") -> str:
    def lk(href, label):
        c = ";color:#b06a06" if active == href else ""
        return f'<a href="{href}" style="{c}">{label}</a>'
    return f"""<div class="topbar">
  <div class="brand"><span class="mark">W</span>Warung Maju</div>
  <div class="nav">{lk('dashboard','Dashboard')}{lk('orders','Orders')}{lk('products','Products')}{lk('sales','Sales')}</div>
  <div class="spacer"></div>
  <span class="owner">Ali &middot; owner</span>
  <a class="logout" href=".">Log out</a>
</div>"""


def _page(title: str, active: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warung Maju — {title}</title><style>{STYLE}</style></head>
<body>{_topbar(active)}<div class="wrap">{body}</div></body></html>"""


def _login_page(error: str = "") -> str:
    err = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warung Maju — Seller sign in</title><style>{STYLE}</style></head>
<body><div class="authwrap"><div class="auth">
  <div class="mark">W</div>
  <h1>Warung Maju</h1>
  <div class="sub">Seller back-office &middot; sign in to your shop</div>
  <form method="POST" action="login">
    <label>Username</label>
    <input name="username" autocomplete="off" placeholder="e.g. smeadmin">
    <label>Password</label>
    <input name="password" type="password" placeholder="Enter password">
    <button type="submit">Sign in</button>
    {err}
  </form>
  <div class="foot">New shop? <a href="register">Register</a> &middot; Protected by ACS Sentinel &middot; access is monitored</div>
</div></div></body></html>"""


def _dashboard_page() -> str:
    body = """
  <div class="h">Sales overview &middot; today</div>
  <div class="stats">
    <div class="stat"><div class="lbl">Sales</div><div class="val">RM 1,840</div></div>
    <div class="stat"><div class="lbl">Orders</div><div class="val">37</div></div>
    <div class="stat"><div class="lbl">Active products</div><div class="val">128</div></div>
    <div class="stat"><div class="lbl">To ship</div><div class="val warn">6</div></div>
  </div>
  <div class="grid2">
    <div class="panel">
      <div class="ph">Recent orders</div>
      <div class="row"><span>#1043 &middot; Siti</span><span class="muted">RM 62.00</span></div>
      <div class="row"><span>#1042 &middot; Kumar</span><span class="muted">RM 118.50</span></div>
      <div class="row"><span>#1041 &middot; Aminah</span><span class="muted">RM 24.90</span></div>
      <div class="row"><span>#1040 &middot; Wei Ling</span><span class="muted">RM 205.00</span></div>
    </div>
    <div class="panel">
      <div class="ph">Products</div>
      <div class="row"><span>Rice 5kg</span><span class="muted">stock 42</span></div>
      <div class="row"><span>Cooking oil 1L</span><span class="muted">stock 18</span></div>
      <div class="row"><span>Sugar 1kg</span><span class="low">stock 3</span></div>
      <div class="row"><span>Teh tarik pack</span><span class="muted">stock 60</span></div>
    </div>
  </div>"""
    return _page("Dashboard", "dashboard", body)


def _orders_page() -> str:
    body = """
  <div class="h">All orders</div>
  <table>
    <tr><th>Order</th><th>Customer</th><th>Items</th><th>Total (RM)</th><th>Status</th></tr>
    <tr><td>#1043</td><td>Siti</td><td>3</td><td>62.00</td><td class="warn">To ship</td></tr>
    <tr><td>#1042</td><td>Kumar</td><td>7</td><td>118.50</td><td class="muted">Shipped</td></tr>
    <tr><td>#1041</td><td>Aminah</td><td>1</td><td>24.90</td><td class="muted">Delivered</td></tr>
    <tr><td>#1040</td><td>Wei Ling</td><td>9</td><td>205.00</td><td class="warn">To ship</td></tr>
    <tr><td>#1039</td><td>Farid</td><td>2</td><td>41.00</td><td class="muted">Delivered</td></tr>
    <tr><td>#1038</td><td>Mei Ying</td><td>4</td><td>88.20</td><td class="muted">Shipped</td></tr>
    <tr><td>#1037</td><td>Raj</td><td>1</td><td>15.00</td><td class="muted">Delivered</td></tr>
  </table>"""
    return _page("Orders", "orders", body)


def _products_page() -> str:
    body = """
  <div class="h">Products</div>
  <table>
    <tr><th>Product</th><th>SKU</th><th>Price (RM)</th><th>Stock</th></tr>
    <tr><td>Rice 5kg</td><td>WM-RIC-05</td><td>32.00</td><td>42</td></tr>
    <tr><td>Cooking oil 1L</td><td>WM-OIL-01</td><td>8.90</td><td>18</td></tr>
    <tr><td>Sugar 1kg</td><td>WM-SUG-01</td><td>3.50</td><td class="low">3</td></tr>
    <tr><td>Teh tarik pack</td><td>WM-TEH-12</td><td>12.90</td><td>60</td></tr>
    <tr><td>Instant noodles x5</td><td>WM-NDL-05</td><td>6.20</td><td>95</td></tr>
    <tr><td>Milo 2kg</td><td>WM-MIL-02</td><td>28.50</td><td class="low">4</td></tr>
    <tr><td>Biscuits assorted</td><td>WM-BIS-01</td><td>9.90</td><td>37</td></tr>
  </table>"""
    return _page("Products", "products", body)


def _sales_page() -> str:
    body = """
  <div class="h">Sales overview</div>
  <div class="stats">
    <div class="stat"><div class="lbl">This week</div><div class="val">RM 11,420</div></div>
    <div class="stat"><div class="lbl">This month</div><div class="val">RM 43,880</div></div>
    <div class="stat"><div class="lbl">Avg order</div><div class="val">RM 49.70</div></div>
    <div class="stat"><div class="lbl">Best day</div><div class="val">Sat</div></div>
  </div>
  <div class="h">Last 7 days</div>
  <table>
    <tr><th>Day</th><th>Orders</th><th>Sales (RM)</th></tr>
    <tr><td>Mon</td><td>28</td><td>1,290</td></tr>
    <tr><td>Tue</td><td>31</td><td>1,455</td></tr>
    <tr><td>Wed</td><td>26</td><td>1,180</td></tr>
    <tr><td>Thu</td><td>34</td><td>1,690</td></tr>
    <tr><td>Fri</td><td>40</td><td>2,105</td></tr>
    <tr><td>Sat</td><td>47</td><td>2,460</td></tr>
    <tr><td>Sun</td><td>37</td><td>1,840</td></tr>
  </table>"""
    return _page("Sales", "sales", body)


def _register_page(error: str = "") -> str:
    note = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warung Maju — Register</title><style>{STYLE}</style></head>
<body><div class="authwrap"><div class="auth">
  <div class="mark">W</div>
  <h1>Warung Maju</h1>
  <div class="sub">Register your shop</div>
  <form method="POST" action="register">
    <label>Shop name</label><input name="business" placeholder="Enter shop name">
    <label>Email</label><input name="email" placeholder="you@example.com">
    <label>Password</label><input name="password" type="password" placeholder="Create password">
    <button type="submit">Create account</button>
    {note}
  </form>
  <div class="foot">Already have a shop? <a href="./">Sign in</a> &middot; monitored by ACS Sentinel</div>
</div></div></body></html>"""


def _not_found_page() -> str:
    return _page("Not found", "",
        '<div class="panel" style="padding:22px"><b>404 — not found</b>'
        '<p class="muted" style="margin-top:8px">The page you requested does not exist on this shop.</p></div>')


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
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    )
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
                "body": json.dumps({"status": "ok", "app": "warung-maju-shop"})}

    if norm_path == "/login" and method == "POST":
        form = _parse_form(body)
        user = form.get("username", "")
        pw   = form.get("password", "")
        if user == DEMO_USER and pw == DEMO_PASS:
            _log_event("LOGIN_SUCCESS", ip, 200, norm_path, payload_size, ua)
            return _html_response(_dashboard_page(), 200)
        else:
            _log_event("LOGIN_FAIL", ip, 401, norm_path, payload_size, ua)
            return _html_response(_login_page("Wrong username or password"), 401)

    # Registration endpoint — another public surface an attacker can hammer.
    if norm_path == "/register":
        if method == "POST":
            _log_event("REGISTER_ATTEMPT", ip, 403, norm_path, payload_size, ua)
            return _html_response(
                _register_page("Registration is currently closed for new shops."), 403)
        _log_event("PAGE_VIEW", ip, 200, norm_path, 0, ua)
        return _html_response(_register_page(), 200)

    # Post-login pages (demo realism — not truly session-protected, but they give
    # the app more legitimate surface and varied page views).
    if norm_path in ("/dashboard", "/orders", "/products", "/sales"):
        page = {
            "/dashboard": _dashboard_page,
            "/orders":    _orders_page,
            "/products":  _products_page,
            "/sales":     _sales_page,
        }[norm_path]
        _log_event("PAGE_VIEW", ip, 200, norm_path, 0, ua)
        return _html_response(page(), 200)

    # Home page = the seller login (the attack surface).
    if norm_path in ("/", ""):
        _log_event("PAGE_VIEW", ip, 200, "/", 0, ua)
        return _html_response(_login_page(), 200)

    # Unknown path -> 404. This is what makes PATH SCANNING detectable: probing
    # /admin, /.env, /wp-login.php, /backup.sql returns 404s, raising the failed
    # count and tripping the scan-probe detection, exactly like a real server.
    _log_event("NOT_FOUND", ip, 404, norm_path, 0, ua)
    return _html_response(_not_found_page(), 404)
