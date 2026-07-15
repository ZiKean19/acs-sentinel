#!/usr/bin/env python3
"""
demo_detection.py — ACS Sentinel deterministic detection demo

Demonstrates the detection engine classifying traffic across ALL severity
tiers, reliably and repeatably, by invoking the Detection Lambda directly with
controlled, complete sliding-window inputs.

Why direct invoke (vs. HTTP attacks)?
-------------------------------------
The production path (attack -> CloudWatch -> Detection Lambda) buffers and
batches log events over ~60s, so the exact window contents that reach the
detector are non-deterministic — making a scripted severity ladder unreliable.
Invoking the detector directly with a precise, complete window gives
deterministic results: each scenario produces exactly its intended severity,
cleanly demonstrating both the rule engine and the Isolation Forest ML.

This exercises the SAME detection code the production path uses. It is the
detection-logic demonstration; the end-to-end WAF enforcement (real HTTP attack
-> 403 block) is demonstrated separately via attack_simulator.py.

Usage
-----
    python demo_detection.py           # runs the full severity ladder
    python demo_detection.py low       # run a single tier

Each scenario uses a DISTINCT source IP (real, routable, correctly
geolocated) so alerts appear as separate entries on the dashboard.
"""

import sys
import json
import gzip
import base64
import io
import time
import subprocess

DETECTION_LAMBDA = "acs-detection-lambda"
AWS_REGION       = "ap-southeast-1"

# Each scenario: distinct real IP (correctly geolocates), plus the traffic
# profile (request count, failure rate) engineered to land in a specific tier.
# MY = Malaysian (geo_anomaly=0), US = foreign (geo_anomaly=1).
SCENARIOS = {
    # name          ip                 geo   n_req  n_fail  expected
    "normal":     ("175.136.60.20",   "MY",   8,     0),    # -> NONE  (no alert)
    "low":        ("175.136.50.10",   "MY",   15,    2),    # -> LOW   (ML)
    "medium":     ("175.136.55.15",   "MY",   25,    6),    # -> MEDIUM(ML)
    "stealth":    ("45.33.32.156",    "US",   40,    14),   # -> HIGH  (ML + geo)
    "bruteforce": ("8.8.8.8",         "US",   55,    55),   # -> HIGH  (rule)
    "flood":      ("208.67.222.222",  "US",   350,   0),    # -> CRITICAL (rule)
}

EXPECTED = {
    "normal":     "NONE (no alert — control)",
    "low":        "LOW  (Isolation Forest / ML)",
    "medium":     "MEDIUM (Isolation Forest / ML)",
    "stealth":    "HIGH (Isolation Forest / ML — under rule thresholds + foreign)",
    "bruteforce": "HIGH (rule engine — high failure rate)",
    "flood":      "CRITICAL (rule engine — DDoS volume)",
}


def _build_event(ip: str, n_req: int, n_fail: int) -> str:
    """
    Build a gzipped+base64 CloudWatch Logs event carrying a complete window of
    n_req requests (n_fail of them failures, placed last so the running failure
    rate rises gradually) from a single IP.
    """
    events = []
    for i in range(n_req):
        is_fail = i >= (n_req - n_fail)  # failures at the end
        status = 401 if is_fail else 200
        events.append({
            "ip": ip,
            "event_type": "LOGIN_FAIL" if is_fail else "PAGE_VIEW",
            "status": status,
            "path": "/login" if is_fail else "/",
            "payload_size": 40 + (i % 20),
        })

    cwl = {
        "messageType": "DATA_MESSAGE",
        "logEvents": [
            {"id": str(i), "timestamp": 0, "message": json.dumps(e)}
            for i, e in enumerate(events)
        ],
    }
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(json.dumps(cwl).encode())
    return json.dumps({"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}})


def _clear_window(ip: str):
    """Clear this IP's sliding-window state so the scenario starts clean."""
    try:
        subprocess.run(
            ["aws", "dynamodb", "delete-item",
             "--table-name", "ip-windows",
             "--key", json.dumps({"ip": {"S": ip}}),
             "--region", AWS_REGION],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass


def run_scenario(name: str):
    if name not in SCENARIOS:
        print(f"Unknown scenario: {name}")
        return
    ip, geo, n_req, n_fail = SCENARIOS[name]
    fail_pct = int((n_fail / n_req) * 100) if n_req else 0

    print(f"\n[{name}]  IP {ip} ({geo})  |  {n_req} requests, {n_fail} failed ({fail_pct}%)")
    print(f"    expected: {EXPECTED[name]}")

    # Clean window first so accumulation from a prior run can't skew it.
    _clear_window(ip)

    payload = _build_event(ip, n_req, n_fail)
    with open("/tmp/_demo_payload.json", "w") as f:
        f.write(payload)

    try:
        result = subprocess.run(
            ["aws", "lambda", "invoke",
             "--function-name", DETECTION_LAMBDA,
             "--payload", "file:///tmp/_demo_payload.json",
             "--cli-binary-format", "raw-in-base64-out",
             "--region", AWS_REGION,
             "/tmp/_demo_response.json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            print(f"    -> sent to detector. Check the dashboard for the alert.")
        else:
            print(f"    -> invoke failed: {result.stderr.strip()}")
    except FileNotFoundError:
        print("    -> ERROR: aws CLI not found. Run this from CloudShell.")
    except Exception as exc:
        print(f"    -> ERROR: {exc}")


def main():
    print("=" * 64)
    print("ACS Sentinel — Detection Severity Demo (deterministic)")
    print("=" * 64)

    if len(sys.argv) > 1:
        run_scenario(sys.argv[1])
    else:
        # Full ladder, in ascending severity order.
        for name in ("normal", "low", "medium", "stealth", "bruteforce", "flood"):
            run_scenario(name)
            time.sleep(3)  # small gap so alerts appear in order on the dashboard

    print("\nDone. Alerts should appear on the dashboard within a few seconds.")
    print("low/medium/stealth = ML (Isolation Forest); bruteforce/flood = rules.")


if __name__ == "__main__":
    main()
