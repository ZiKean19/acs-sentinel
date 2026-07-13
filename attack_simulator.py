#!/usr/bin/env python3
"""
attack_simulator.py — ACS Sentinel Attack Simulator (live AWS)

Generates realistic attack traffic against the deployed target application to
exercise the full detection-and-response pipeline:

    attack -> target Lambda -> CloudWatch -> Detection Lambda
           -> DynamoDB alert -> WAF auto-block -> HTTP 403

Scenarios
---------
  bruteforce : many failed logins from one IP  -> rule engine -> HIGH/CRITICAL
  stealth    : low-and-slow mixed traffic       -> Isolation Forest -> MEDIUM/HIGH
  flood      : high request volume              -> rule engine -> CRITICAL (DDoS)
  low        : direct-invoke with a Malaysian IP -> Isolation Forest -> LOW
  normal     : benign traffic                   -> no detection (control test)

Usage
-----
    python attack_simulator.py bruteforce
    python attack_simulator.py stealth
    python attack_simulator.py flood
    python attack_simulator.py low          # requires boto3 + AWS creds
    python attack_simulator.py normal
    python attack_simulator.py all          # runs each in sequence

Notes
-----
  * The target URL points at the REST API (WAF-protected) by default so you can
    observe the 403 block. Override with --url if needed.
  * Detection runs ~60-90s after the attack because CloudWatch Logs buffers
    before delivering to the Detection Lambda. Be patient before checking the
    dashboard / DynamoDB.
  * The HTTP scenarios (bruteforce/stealth/flood/normal) need only the standard
    library. The 'low' scenario needs boto3 + AWS credentials, because LOW
    severity requires a *Malaysian* source IP that is only mildly anomalous —
    which cannot be produced from a real foreign attacker IP (those get bumped
    to MEDIUM by the geo rule). It therefore invokes the Detection Lambda
    directly with a synthetic Malaysian-IP event. This tests the detection
    *logic* rather than the HTTP path, and is documented as such.
"""

import sys
import time
import json
import gzip
import base64
import io
import argparse
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Default target = WAF-protected REST API (so you can see the 403 block).
DEFAULT_URL = "https://6s2k83zyo0.execute-api.ap-southeast-1.amazonaws.com/prod"

VALID_USER = "smeadmin"
VALID_PASS = "portal2026"

# Detection Lambda + region, used by the `low` scenario's direct-invoke path.
DETECTION_LAMBDA = "acs-detection-lambda"
AWS_REGION       = "ap-southeast-1"
# A Malaysian IP prefix so the geo lookup resolves to MY (geo_anomaly=0),
# which is required for a LOW severity result (foreign IPs get bumped up).
MALAYSIAN_IP     = "175.136.1.100"


def _post_login(base_url: str, username: str, password: str, timeout: float = 5.0) -> int:
    """Send one POST /login, return the HTTP status code (or 0 on error)."""
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{base_url}/login", data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code          # 401 (bad creds) or 403 (WAF block) land here
    except Exception:
        return 0


def _get_page(base_url: str, timeout: float = 5.0) -> int:
    req = urllib.request.Request(f"{base_url}/", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _summarise(codes: list):
    from collections import Counter
    counts = Counter(codes)
    parts = [f"{code}: {n}" for code, n in sorted(counts.items())]
    print("   status codes -> " + ", ".join(parts))
    if 403 in counts:
        print("   >> 403 seen: WAF is actively blocking this IP.")


def attack_bruteforce(base_url: str, n: int = 60):
    """Many failed logins -> high failure rate -> rule engine -> HIGH/CRITICAL."""
    print(f"[bruteforce] Sending {n} failed logins to {base_url}/login ...")
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(_post_login, base_url, "admin", f"wrong{i}") for i in range(n)]
        codes = [f.result() for f in futures]
    _summarise(codes)


def attack_flood(base_url: str, n: int = 350):
    """High request volume -> DDoS rule -> CRITICAL."""
    print(f"[flood] Sending {n} rapid requests to {base_url}/ ...")
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(_get_page, base_url) for _ in range(n)]
        codes = [f.result() for f in futures]
    _summarise(codes)


def attack_stealth(base_url: str, total: int = 40, fail_ratio: float = 0.35):
    """
    Low-and-slow mixed traffic that stays UNDER the rule thresholds
    (< 60 requests, < 50% failure) so only the Isolation Forest flags it.
    """
    n_fail = int(total * fail_ratio)
    n_ok = total - n_fail
    print(f"[stealth] Sending {total} mixed requests "
          f"({n_ok} valid, {n_fail} failed, ~{int(fail_ratio*100)}% failure) ...")
    print("   (stays under rule thresholds -> should be caught by ML, not rules)")
    codes = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(n_ok):
            futures.append(pool.submit(_post_login, base_url, VALID_USER, VALID_PASS))
        for i in range(n_fail):
            futures.append(pool.submit(_post_login, base_url, "admin", f"wrong{i}"))
        codes = [f.result() for f in futures]
    _summarise(codes)


def attack_normal(base_url: str, n: int = 8):
    """Benign traffic — control test. Should NOT trigger detection."""
    print(f"[normal] Sending {n} benign page views + a valid login ...")
    codes = []
    for _ in range(n):
        codes.append(_get_page(base_url))
        time.sleep(0.5)
    codes.append(_post_login(base_url, VALID_USER, VALID_PASS))
    _summarise(codes)


def attack_low(base_url: str = None):
    """
    Produce a genuine LOW-severity alert.

    LOW severity requires a *Malaysian* source IP (geo_anomaly=0) that is only
    marginally anomalous. A real foreign attacker IP can't produce this — the
    geo rule bumps foreign LOW up to MEDIUM. So this scenario invokes the
    Detection Lambda directly with a synthetic CloudWatch event carrying a
    Malaysian IP and mildly-anomalous, low-volume traffic.

    This tests the detection *logic* (severity banding), not the HTTP path.
    """
    try:
        import json, gzip, base64, io
        import boto3
    except ImportError:
        print("[low] boto3 is required for this scenario: pip install boto3")
        return

    REGION = "ap-southeast-1"
    FUNCTION = "acs-detection-lambda"
    # A real Malaysian IP block (TM/Unifi range) so GeoLite2 resolves it to MY.
    MY_IP = "175.136.100.50"

    # Mildly anomalous: low volume, modest failure rate, small payload variance.
    # Sent as several events so the sliding window accumulates a small count
    # that nudges the Isolation Forest just past its threshold -> LOW.
    log_events = []
    for i in range(12):
        status = 401 if i % 5 == 0 else 200      # ~20% failure rate
        log_events.append({
            "ip": MY_IP,
            "event_type": "LOGIN_FAIL" if status == 401 else "PAGE_VIEW",
            "status": status,
            "path": "/login",
            "payload_size": 40 + (i * 3),
        })

    cwl = {
        "messageType": "DATA_MESSAGE",
        "logEvents": [
            {"id": str(i), "timestamp": 0, "message": json.dumps(e)}
            for i, e in enumerate(log_events)
        ],
    }
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(json.dumps(cwl).encode())
    payload = json.dumps({"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}})

    print(f"[low] Invoking {FUNCTION} directly with a Malaysian IP ({MY_IP}) ...")
    print("   (synthetic event — tests severity logic, not the HTTP path)")
    client = boto3.client("lambda", region_name=REGION)
    try:
        resp = client.invoke(
            FunctionName=FUNCTION,
            Payload=payload.encode(),
        )
        result = resp["Payload"].read().decode()
        print(f"   Lambda response: {result}")
        print("   Check DynamoDB / dashboard for a LOW-severity alert from this IP.")
    except Exception as exc:
        print(f"   Invoke failed: {exc}")


def attack_low(base_url: str = None):
    """
    LOW severity — direct Detection Lambda invoke.

    LOW is only produced for mildly-anomalous traffic from a MALAYSIAN IP
    (foreign IPs get their severity bumped up a band). Since a real attack
    from this machine would carry a non-Malaysian IP, this scenario tests the
    detection/severity logic directly by invoking the Detection Lambda with a
    synthetic CloudWatch event carrying a Malaysian source IP and low-intensity
    features. This produces a genuine LOW alert in DynamoDB that appears on the
    dashboard.

    Note: this is a logic/severity test path, not an over-the-network HTTP
    attack — it exists to demonstrate the LOW tier end-to-end.
    """
    print("[low] Direct-invoking Detection Lambda with a Malaysian IP + mild anomaly ...")
    print("      (LOW requires domestic traffic; real attacks from here look foreign)")

    # Build several mildly-anomalous events from the same Malaysian IP so the
    # sliding window accumulates a small-but-unusual pattern (a few failures,
    # modest volume) — enough for the Isolation Forest to flag as LOW.
    log_events = []
    for i in range(12):
        status = 401 if i % 5 == 0 else 200  # ~20% failure — mild
        log_events.append({
            "ip": MALAYSIAN_IP,
            "event_type": "LOGIN_FAIL" if status == 401 else "PAGE_VIEW",
            "status": status,
            "path": "/login",
            "payload_size": 40 + i,
        })

    cwl = {
        "messageType": "DATA_MESSAGE",
        "logEvents": [
            {"id": str(i), "timestamp": 0, "message": json.dumps(e)}
            for i, e in enumerate(log_events)
        ],
    }

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(json.dumps(cwl).encode())
    payload = json.dumps({"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}})

    try:
        with open("/tmp/_low_payload.json", "w") as f:
            f.write(payload)
        result = subprocess.run(
            ["aws", "lambda", "invoke",
             "--function-name", DETECTION_LAMBDA,
             "--payload", "file:///tmp/_low_payload.json",
             "--cli-binary-format", "raw-in-base64-out",
             "--region", AWS_REGION,
             "/tmp/_low_response.json"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            print("   Detection Lambda invoked successfully.")
            print("   Check the dashboard / alerts table for a LOW severity entry.")
        else:
            print(f"   Invoke failed: {result.stderr.strip()}")
    except FileNotFoundError:
        print("   ERROR: aws CLI not found. Run this scenario from CloudShell or a")
        print("          machine with the AWS CLI configured.")
    except Exception as exc:
        print(f"   ERROR: {exc}")


SCENARIOS = {
    "bruteforce": attack_bruteforce,
    "stealth":    attack_stealth,
    "flood":      attack_flood,
    "low":        attack_low,
    "normal":     attack_normal,
}


def main():
    parser = argparse.ArgumentParser(description="ACS Sentinel attack simulator")
    parser.add_argument("scenario", choices=list(SCENARIOS.keys()) + ["all"],
                        help="Which attack scenario to run")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="Target base URL (default: WAF-protected REST API)")
    args = parser.parse_args()

    print("=" * 64)
    print(f"ACS Sentinel Attack Simulator  |  target: {args.url}")
    print("=" * 64)

    if args.scenario == "all":
        for name in ("normal", "low", "stealth", "bruteforce", "flood"):
            SCENARIOS[name](args.url)
            print(f"   ...pausing 15s before next scenario...\n")
            time.sleep(15)
    else:
        SCENARIOS[args.scenario](args.url)

    print("\nDone. Detection runs ~60-90s after the attack (CloudWatch buffer).")
    print("Check your dashboard, or scan DynamoDB, to see alerts + blocks appear.")


if __name__ == "__main__":
    main()
