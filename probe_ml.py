#!/usr/bin/env python3
"""
probe_ml.py — Discover the DEPLOYED model's real scoring behaviour.

Sends a sweep of traffic profiles (each from a fresh Malaysian IP so
geo_anomaly=0 and we isolate pure ML behaviour) to the live Detection Lambda,
then reads back the scores it actually produced from the log-stream table.

Run this in CloudShell:  python probe_ml.py
"""

import json, gzip, base64, io, time, subprocess

REGION = "ap-southeast-1"
LAMBDA = "acs-detection-lambda"

# (label, n_requests, n_failures) — each gets its own fresh Malaysian IP.
PROFILES = [
    ("baseline",   5,   0),
    ("mild-a",     10,  1),
    ("mild-b",     15,  2),
    ("moderate-a", 20,  4),
    ("moderate-b", 25,  6),
    ("elevated-a", 30,  9),
    ("elevated-b", 40,  14),
    ("high-vol",   50,  10),
]

# Distinct Malaysian IPs (real, routable, geolocate to MY).
BASE_IPS = ["60.48.200.{}".format(i) for i in range(10, 10 + len(PROFILES))]


def _aws(args, timeout=60):
    return subprocess.run(["aws"] + args + ["--region", REGION],
                          capture_output=True, text=True, timeout=timeout)


def _build_payload(ip, n_req, n_fail):
    events = []
    for i in range(n_req):
        is_fail = i >= (n_req - n_fail)
        events.append({
            "ip": ip,
            "event_type": "LOGIN_FAIL" if is_fail else "PAGE_VIEW",
            "status": 401 if is_fail else 200,
            "path": "/login" if is_fail else "/",
            "payload_size": 45,
        })
    cwl = {"messageType": "DATA_MESSAGE",
           "logEvents": [{"id": str(i), "timestamp": 0, "message": json.dumps(e)}
                         for i, e in enumerate(events)]}
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(json.dumps(cwl).encode())
    return json.dumps({"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}})


def _clear(ip):
    key = json.dumps({"ip": {"S": ip}})
    _aws(["dynamodb", "delete-item", "--table-name", "ip-windows", "--key", key])
    _aws(["dynamodb", "delete-item", "--table-name", "blocked-ips", "--key", key])


def _scores_for(ip):
    """Return the list of scores the detector logged for this IP."""
    r = _aws(["dynamodb", "scan", "--table-name", "log-stream",
              "--filter-expression", "source_ip = :ip",
              "--expression-attribute-values", json.dumps({":ip": {"S": ip}}),
              "--projection-expression", "score,#l",
              "--expression-attribute-names", json.dumps({"#l": "level"}),
              "--output", "json"])
    if r.returncode != 0:
        return []
    try:
        items = json.loads(r.stdout).get("Items", [])
    except Exception:
        return []
    out = []
    for it in items:
        s = it.get("score", {}).get("N")
        lv = it.get("level", {}).get("S", "?")
        if s is not None:
            out.append((float(s), lv))
    return out


def main():
    print("=" * 72)
    print("Probing the DEPLOYED model — pure ML behaviour (Malaysian IPs, geo=0)")
    print("=" * 72)

    for (label, n_req, n_fail), ip in zip(PROFILES, BASE_IPS):
        _clear(ip)
        payload = _build_payload(ip, n_req, n_fail)
        with open("/tmp/_probe.json", "w") as f:
            f.write(payload)
        _aws(["lambda", "invoke", "--function-name", LAMBDA,
              "--payload", "file:///tmp/_probe.json",
              "--cli-binary-format", "raw-in-base64-out", "/tmp/_probe_resp.json"])
        pct = int(n_fail / n_req * 100) if n_req else 0
        print(f"  sent {label:11} {ip:15} {n_req:3} req, {n_fail:2} fail ({pct:2}%)")

    print("\nWaiting 8s for writes to settle...\n")
    time.sleep(8)

    print(f"{'profile':12} {'req':>4} {'fail%':>6} {'min score':>10} {'max score':>10}  levels")
    print("-" * 72)
    for (label, n_req, n_fail), ip in zip(PROFILES, BASE_IPS):
        scores = _scores_for(ip)
        pct = int(n_fail / n_req * 100) if n_req else 0
        if not scores:
            print(f"{label:12} {n_req:4} {pct:5}% {'—':>10} {'—':>10}  (no log entries)")
            continue
        vals = [s for s, _ in scores]
        levels = sorted({lv for _, lv in scores})
        print(f"{label:12} {n_req:4} {pct:5}% {min(vals):10.4f} {max(vals):10.4f}  {','.join(levels)}")

    print("\nNEGATIVE score = anomalous per the model. POSITIVE = normal.")
    print("Send this table back to tune the demo scenarios to the REAL model.")


if __name__ == "__main__":
    main()
