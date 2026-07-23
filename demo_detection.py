#!/usr/bin/env python3
"""
demo_detection.py — ACS Sentinel detection demo (ML-led, deterministic)

Shows the detection engine classifying traffic across every severity tier by
invoking the Detection Lambda directly with controlled, complete sliding-window
inputs, then reading back the ACTUAL score + severity the engine assigned.

Design of this demo
-------------------
The star is the Isolation Forest (ML), demonstrated on LOCAL Malaysian source
IPs (geo_anomaly = 0) with traffic kept UNDER the rule-engine thresholds
(failed_count < 5, total_requests < 60) so that ONLY the ML fires. This proves
the ML earns its place: it flags increasingly anomalous local traffic that the
deterministic rules never see.

The rule engine is shown as a SUPPORTING act (bruteforce, flood) — the loud,
obvious attacks any signature system would catch. A single FOREIGN cameo shows
the geo_anomaly feature nudging severity up.

Why direct invoke (vs. real HTTP attacks)?
------------------------------------------
The production path (attack -> CloudWatch -> Detection Lambda) batches log
events over ~60s, so the exact window that reaches the detector is
non-deterministic — unreliable for a scripted severity ladder. Direct invoke
with a precise, complete window is deterministic. This exercises the SAME
detection code the production path runs. The end-to-end WAF block (real HTTP ->
403) is demonstrated separately by attack_simulator.py.

Note on ML tiers
----------------
The exact tier a profile lands in depends on the trained model's score
distribution. This script READS BACK and prints the real score + severity after
each scenario, so what you present is always the engine's actual output. If a
tier lands a band off from the label, nudge that scenario's numbers — the
read-back tells you immediately.

Usage
-----
    python demo_detection.py           # full ladder, ML-led
    python demo_detection.py ml_high   # a single scenario
"""

import sys
import json
import gzip
import base64
import io
import time
import subprocess

DETECTION_LAMBDA = "acs-detection-lambda"
ALERTS_TABLE     = "alerts"
AWS_REGION       = "ap-southeast-1"

# name -> (ip, geo, n_req, n_fail, var)
#   geo   : "MY" local (geo_anomaly=0) or "US" foreign (geo_anomaly=1)
#   n_req : requests in the 60s window
#   n_fail: failed (401) requests  — keep < 5 for pure-ML scenarios
#   var   : "flat" (uniform payloads) or "spread" (high payload-size variance,
#           an ML-only signal — no rule watches it below 1e10)
#
# MAIN ACT — Isolation Forest on LOCAL Malaysian IPs, under every rule threshold.
# SUPPORTING — rule engine (bruteforce, flood). CAMEO — foreign geo bump.
SCENARIOS = {
    "normal":     ("175.136.60.20", "MY",   8,   0, "flat"),    # control -> no alert
    "ml_low":     ("175.136.50.10", "MY",  15,   2, "flat"),    # ML
    "ml_medium":  ("175.136.55.15", "MY",  32,   3, "spread"),  # ML
    "ml_high":    ("175.136.58.22", "MY",  55,   4, "spread"),  # ML (still < rules)
    "bruteforce": ("175.136.70.30", "MY",  22,  20, "flat"),    # rule (failed_count >= 15)
    "flood":      ("175.136.80.40", "MY", 320,   0, "flat"),    # rule (requests >= 300)
    "foreign":    ("45.33.32.156",  "US",  32,   3, "spread"),  # cameo — geo bump
}

EXPECTED = {
    "normal":     "NONE — control, no alert",
    "ml_low":     "ML (Isolation Forest) — mild local anomaly",
    "ml_medium":  "ML (Isolation Forest) — moderate local anomaly",
    "ml_high":    "ML (Isolation Forest) — strong local anomaly, still under rules",
    "bruteforce": "RULE — brute force (failed_count >= 15)",
    "flood":      "RULE — DDoS volume (requests >= 300)",
    "foreign":    "ML + geo — same profile as ml_medium but foreign, bumped up",
}

ORDER = ["normal", "ml_low", "ml_medium", "ml_high", "bruteforce", "flood", "foreign"]


def _build_event(ip: str, n_req: int, n_fail: int, var: str) -> str:
    """Gzip+base64 CloudWatch Logs event = one complete window of n_req requests
    (n_fail failures, placed last so the failure count rises gradually) from ip.
    var='spread' injects a few large payloads to raise payload_size_variance —
    a pure-ML signal that trips no rule."""
    events = []
    for i in range(n_req):
        is_fail = i >= (n_req - n_fail)
        if var == "spread" and i % 7 == 0:
            size = 90_000 + (i * 1500)     # occasional big payloads -> high variance
        else:
            size = 40 + (i % 20)
        events.append({
            "ip": ip,
            "event_type": "LOGIN_FAIL" if is_fail else "PAGE_VIEW",
            "status": 401 if is_fail else 200,
            "path": "/login" if is_fail else "/",
            "payload_size": size,
        })
    cwl = {
        "messageType": "DATA_MESSAGE",
        "logEvents": [{"id": str(i), "timestamp": 0, "message": json.dumps(e)}
                      for i, e in enumerate(events)],
    }
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(json.dumps(cwl).encode())
    return json.dumps({"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}})


def _aws(args, **kw):
    return subprocess.run(["aws", *args, "--region", AWS_REGION],
                          capture_output=True, text=True, timeout=60, **kw)


def _clear_window(ip: str):
    """Reset this IP's sliding-window state so the scenario starts clean."""
    try:
        _aws(["dynamodb", "delete-item", "--table-name", "ip-windows",
              "--key", json.dumps({"ip": {"S": ip}})])
    except Exception:
        pass


def _read_back(ip: str):
    """Query the alerts table and print the engine's ACTUAL verdict for this IP —
    the real score + severity, not a guess. This is the ML demonstration."""
    time.sleep(2)  # let the write land
    try:
        r = _aws(["dynamodb", "scan", "--table-name", ALERTS_TABLE,
                  "--filter-expression", "source_ip = :ip",
                  "--expression-attribute-values", json.dumps({":ip": {"S": ip}}),
                  "--output", "json"])
        items = json.loads(r.stdout or "{}").get("Items", [])
        if not items:
            print("    -> ACTUAL: no alert (classified NONE / below threshold)")
            return
        newest = max(items, key=lambda it: it.get("timestamp", {}).get("S", ""))
        sev    = newest.get("severity", {}).get("S", "?")
        score  = newest.get("score", {}).get("N", "?")
        threat = newest.get("type", {}).get("S", "")
        engine = "rule" if str(score) in ("-0.3", "-0.6", "-0.8", "-1.0") else "isolation_forest"
        print(f"    -> ACTUAL: {sev:<8} score={score:<10} {threat}  [{engine}]")
    except Exception as exc:
        print(f"    -> read-back failed: {exc}")


def run_scenario(name: str):
    if name not in SCENARIOS:
        print(f"Unknown scenario: {name}")
        return
    ip, geo, n_req, n_fail, var = SCENARIOS[name]
    print(f"\n[{name}]  IP {ip} ({geo})  |  {n_req} req, {n_fail} failed, payload={var}")
    print(f"    expected: {EXPECTED[name]}")

    _clear_window(ip)
    payload = _build_event(ip, n_req, n_fail, var)
    with open("/tmp/_demo_payload.json", "w") as f:
        f.write(payload)

    try:
        result = _aws(["lambda", "invoke", "--function-name", DETECTION_LAMBDA,
                       "--payload", "file:///tmp/_demo_payload.json",
                       "--cli-binary-format", "raw-in-base64-out",
                       "/tmp/_demo_response.json"])
        if result.returncode != 0:
            print(f"    -> invoke failed: {result.stderr.strip()}")
            return
    except FileNotFoundError:
        print("    -> ERROR: aws CLI not found. Run this from CloudShell.")
        return
    except Exception as exc:
        print(f"    -> ERROR: {exc}")
        return

    _read_back(ip)


def main():
    print("=" * 68)
    print("ACS Sentinel — Detection demo (ML-led, local traffic)")
    print("=" * 68)
    print("Main act: Isolation Forest on LOCAL Malaysian IPs (rules stay silent).")
    print("Supporting: rule engine (bruteforce, flood). Cameo: foreign geo bump.\n")

    if len(sys.argv) > 1:
        run_scenario(sys.argv[1])
    else:
        for name in ORDER:
            run_scenario(name)
            time.sleep(3)

    print("\nDone. Each line's ACTUAL row is the engine's real output.")
    print("ml_* = Isolation Forest; bruteforce/flood = rules; foreign = geo bump.")


if __name__ == "__main__":
    main()
