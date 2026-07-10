"""
target-app/app.py — Simulated Print-on-Demand Business Application

This app has ZERO ACS Sentinel code inside it.

The only integration with ACS is:
  1. This app sends structured JSON logs to AWS CloudWatch Logs.
  2. ACS reads those logs (via Nginx access log or CloudWatch Subscription Filter).
  3. That is all.

To integrate ACS with YOUR real application, you only need to do the same:
  - Call push_log() (or equivalent in your language) on each request.
  - Everything else — detection, blocking, dashboard — is handled by ACS.
"""

import os
import json
import time
import uuid
import threading
from datetime import datetime, timezone

import boto3
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "docx"}

# ── AWS CloudWatch client ─────────────────────────────────────────────────────
LOCALSTACK_URL = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
_AWS = dict(
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    endpoint_url=LOCALSTACK_URL,
)
logs_client = boto3.client("logs", **_AWS)
LOG_GROUP   = "security-logs"
LOG_STREAM  = "app-events"

PAPER_PRICES = {
    "simili_bw":        0.05,
    "simili_colour":    0.20,
    "art_paper_bw":     0.15,
    "art_paper_colour": 0.50,
    "glossy_colour":    0.70,
}

# ── ACS Integration: The ONLY function your app needs ─────────────────────────

def push_log(event_type: str, extra: dict):
    """
    Send a structured log event to CloudWatch Logs.
    ACS Sentinel reads these events and analyses them for threats.

    This is the complete integration surface between your app and ACS.
    You can call this from any framework (Django, FastAPI, Express, etc.)
    by simply replacing this boto3 call with the equivalent SDK call.
    """
    payload = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "ip":         request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        **extra,
    }
    def _send():
        try:
            logs_client.put_log_events(
                logGroupName=LOG_GROUP,
                logStreamName=LOG_STREAM,
                logEvents=[{
                    "timestamp": int(time.time() * 1000),
                    "message":   json.dumps(payload),
                }],
            )
        except Exception:
            pass  # Never let logging failure break the business app
    threading.Thread(target=_send, daemon=True).start()

# ── Business Routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    push_log("PAGE_VIEW", {"page": "index"})
    return render_template("index.html", paper_types=list(PAPER_PRICES.keys()))


@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    success  = bool(username)
    push_log("LOGIN_ATTEMPT", {"username": username, "success": success})
    if success:
        return jsonify({"status": "ok", "message": "Login successful."})
    return jsonify({"status": "error", "message": "Invalid credentials."}), 401


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part."}), 400
    file       = request.files["file"]
    paper_type = request.form.get("paper_type", "simili_bw")
    copies     = int(request.form.get("copies", 1))

    if not file.filename or "." not in file.filename:
        return jsonify({"error": "Invalid file."}), 400
    ext = file.filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file type."}), 400

    filename  = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{filename}")
    file.save(save_path)
    file_size = os.path.getsize(save_path)

    price_per_copy = PAPER_PRICES.get(paper_type, 0.05)
    est_pages      = max(1, file_size // (100 * 1024))
    total_price    = round(price_per_copy * est_pages * copies, 2)
    order_id       = str(uuid.uuid4())

    push_log("FILE_UPLOAD", {
        "order_id":    order_id,
        "file_size":   file_size,
        "paper_type":  paper_type,
        "copies":      copies,
        "total_price": total_price,
    })
    return jsonify({
        "order_id":        order_id,
        "estimated_pages": est_pages,
        "total_price_myr": total_price,
        "message":         "Order submitted successfully.",
    })


@app.route("/pay", methods=["POST"])
def pay():
    data = request.get_json(silent=True) or request.form
    push_log("PAYMENT_REQUEST", {
        "order_id": data.get("order_id", ""),
        "amount":   data.get("amount", 0),
        "method":   data.get("method", "unknown"),
    })
    return jsonify({"status": "paid", "order_id": data.get("order_id", ""), "amount": data.get("amount", 0)})


@app.route("/admin/orders")
def admin_orders():
    push_log("ADMIN_ACCESS", {"endpoint": "/admin/orders"})
    return jsonify({"message": "Admin endpoint — triggers ACS anomaly detection."})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
