# -*- coding: utf-8 -*-
"""
attack_simulator.py — Simulates attack traffic against the target application.

Usage: python attack_simulator.py
Make sure the Docker Compose stack is running first (docker compose up -d).

Attack sequence:
  STEP 0 — Normal background traffic
  STEP 1 — Brute Force Login        (Malaysian IP -> HIGH/CRITICAL via RULE)
  STEP 2 — Low Severity Anomaly     (Foreign IP   -> LOW via RULE)
  STEP 3 — Mass File Upload         (Malaysian IP -> MEDIUM via RULE)
  STEP 4 — DDoS Request Flood       (Malaysian IP -> HIGH via RULE)
  STEP 5 — Combined Blitz           (Malaysian IP -> CRITICAL via RULE)
  STEP 6 — Stealth ML-Only Attack   (Malaysian IP -> HIGH via ISOLATION FOREST)

Steps 1 to 5 are caught by the rule engine.
Step 6 stays deliberately below every rule threshold — only the Isolation
Forest flags it, demonstrating the ML layer catches what rules miss.
"""

import sys
import requests
import time
import os
import threading
import random

BASE_URL = "http://127.0.0.1"

SESSION = requests.Session()
SESSION.trust_env = False
SESSION.proxies   = {"http": None, "https": None}


# ── IP Generators ─────────────────────────────────────────────────────────────

def random_public_ip():
    """Returns a random plausible foreign (non-Malaysian) public IP address."""
    while True:
        first = random.randint(1, 223)
        if first not in (60, 49, 103, 115, 175, 183, 210):
            return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_malaysian_ip():
    """Returns a random IP from Malaysian ISP prefixes (geo_anomaly=0)."""
    prefixes = ["175.136", "175.143", "183.171", "210.186", "60.48", "49.128", "103.28", "115.164"]
    pfx = random.choice(prefixes)
    return f"{pfx}.{random.randint(0,255)}.{random.randint(1,254)}"


def separator(title):
    print("\n" + "=" * 56)
    print("  " + title)
    print("=" * 56)


def ok(msg):   print("  [OK]  " + msg)
def info(msg): print("  [..]  " + msg)
def warn(msg): print("  [!!]  " + msg)


# ── STEP 0 — Normal Background Traffic ───────────────────────────────────────

def normal_background_traffic(duration_sec: int = 15):
    separator("TRAFFIC: Normal Background Users (%ds)" % duration_sec)
    info("Simulating healthy standard platform usage (Malaysian IPs)...")
    start = time.time()
    count = 0
    while time.time() - start < duration_sec:
        ip      = random_malaysian_ip()
        headers = {"X-Forwarded-For": ip}
        try:
            SESSION.get(BASE_URL + "/", headers=headers, timeout=10)
            if count % 10 == 0:
                SESSION.post(
                    BASE_URL + "/login",
                    json={"username": "user%d" % count, "password": "password"},
                    headers=headers,
                    timeout=10,
                )
            count += 1
        except Exception:
            pass
        time.sleep(0.5)
    ok("Sent %d normal background requests." % count)


# ── STEP 1 — Brute Force Login ────────────────────────────────────────────────

def brute_force_login(attempts: int = 80):
    separator("STEP 1 [RULE -> HIGH/CRITICAL] Brute Force Login — Malaysian IP")
    info("Rule triggers: failed_status_rate >= 0.5")
    ip      = random_malaysian_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=0)" % ip)
    count = 0
    for i in range(attempts):
        try:
            SESSION.post(
                BASE_URL + "/login",
                json={"username": "", "password": "wrong%d" % i},
                headers=headers,
                timeout=10,
            )
            count += 1
        except Exception as e:
            warn(str(e))
        time.sleep(0.35)
    ok("Sent %d failed login requests -> expect RULE detection, HIGH/CRITICAL severity" % count)


# ── STEP 2 — Low Severity Geo-Anomaly ────────────────────────────────────────

def low_severity_anomaly():
    separator("STEP 2 [RULE -> LOW] Geo-Anomaly + Slow Brute Force — Foreign IP")
    info("Rule triggers: geo_anomaly=1 (foreign IP) + failed_status_rate raises")
    ip      = random_public_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=1)" % ip)
    count = 0
    for i in range(8):
        try:
            SESSION.post(
                BASE_URL + "/login",
                json={"username": "", "password": "wrong%d" % i},
                headers=headers,
                timeout=10,
            )
            count += 1
        except Exception as e:
            warn(str(e))
        time.sleep(0.9)
    ok("Sent %d failed login requests -> expect RULE detection, LOW severity" % count)


# ── STEP 3 — Mass File Upload ─────────────────────────────────────────────────

def medium_severity_anomaly(count: int = 16):
    separator("STEP 3 [RULE -> MEDIUM] Mass File Upload — Malaysian IP")
    info("Rule triggers: payload_size_variance will spike significantly")
    ip      = random_malaysian_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=0)" % ip)
    tmp = "medium_test_file.pdf"
    with open(tmp, "wb") as f:
        f.write(b"%PDF-1.4\n" + b"X" * 512_000)
    done = 0
    for i in range(count):
        try:
            with open(tmp, "rb") as f:
                SESSION.post(
                    BASE_URL + "/upload",
                    files={"file": ("mal_%d.pdf" % i, f, "application/pdf")},
                    data={"paper_type": "simili_bw", "copies": "1"},
                    headers=headers,
                    timeout=5,
                )
            done += 1
        except Exception as e:
            warn(str(e))
        time.sleep(0.3)
    try:
        os.remove(tmp)
    except Exception:
        pass
    ok("Sent %d upload requests -> expect RULE detection, MEDIUM severity" % done)


# ── STEP 4 — Request Flood / DDoS ────────────────────────────────────────────

def high_request_rate(duration_sec: int = 20):
    separator("STEP 4 [RULE -> HIGH] Request Flood / DDoS — Malaysian IP")
    info("Rule triggers: total_requests >= 60 in 60s window")
    ip      = random_malaysian_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=0)" % ip)
    start = time.time()
    count = 0
    while time.time() - start < duration_sec:
        try:
            SESSION.get(BASE_URL + "/", headers=headers, timeout=10)
            count += 1
        except Exception:
            pass
        time.sleep(0.033)
    rate = count / duration_sec
    ok("Sent %d requests (%.0f req/sec = %.0f req/min) -> expect RULE detection, HIGH/CRITICAL"
       % (count, rate, rate * 60))


# ── STEP 5 — Combined Blitz ───────────────────────────────────────────────────

def combined_blitz():
    separator("STEP 5 [RULE -> CRITICAL] Combined Blitz Attack — Malaysian IP")
    info("All attack types in parallel: login flood + admin probe + request flood + mass upload")
    ip      = random_malaysian_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=0)" % ip)

    def do_logins():
        for i in range(200):
            try:
                SESSION.post(BASE_URL + "/login",
                             json={"username": "", "password": "x%d" % i},
                             headers=headers, timeout=10)
            except Exception:
                pass
            time.sleep(0.02)

    def do_admin():
        for _ in range(50):
            try:
                SESSION.get(BASE_URL + "/admin/orders", headers=headers, timeout=10)
            except Exception:
                pass
            time.sleep(0.1)

    def do_flood():
        end = time.time() + 25
        while time.time() < end:
            try:
                SESSION.get(BASE_URL + "/", headers=headers, timeout=10)
            except Exception:
                pass
            time.sleep(0.03)

    def do_uploads():
        tmp = "blitz_file.pdf"
        with open(tmp, "wb") as f:
            f.write(b"%PDF-1.4\n" + b"X" * 51_200)
        for i in range(30):
            try:
                with open(tmp, "rb") as f:
                    SESSION.post(BASE_URL + "/upload",
                                 files={"file": ("blitz_%d.pdf" % i, f, "application/pdf")},
                                 data={"paper_type": "simili_bw", "copies": "1"},
                                 headers=headers, timeout=5)
            except Exception:
                pass
            time.sleep(0.1)
        try:
            os.remove(tmp)
        except Exception:
            pass

    threads = [
        threading.Thread(target=do_logins,  daemon=True),
        threading.Thread(target=do_admin,   daemon=True),
        threading.Thread(target=do_flood,   daemon=True),
        threading.Thread(target=do_uploads, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok("Blitz complete -> expect RULE detection, CRITICAL severity")


# ── STEP 6 — Stealth ML-Only Attack ──────────────────────────────────────────

def stealth_ml_attack():
    separator("STEP 6 [ISOLATION FOREST ONLY] Stealth Multi-Vector — Malaysian IP")
    info("All individual metrics stay BELOW every rule threshold.")
    info("Rules will NOT fire. Only the Isolation Forest ML engine will flag this.")
    info("")
    info("Rule thresholds for reference:")
    info("  total_requests      < 60   (we target ~50)")
    info("  failed_status_rate  < 0.5  (we target ~0.4)")
    info("  payload_variance    < 1e10 (large files create moderate variance)")
    info("  geo_anomaly         = 0    (Malaysian IP)")
    info("")
    info("The COMBINATION of these signals is statistically anomalous.")
    info("The Isolation Forest detects the pattern even though no single rule fires.")

    ip      = random_malaysian_ip()
    headers = {"X-Forwarded-For": ip}
    info("Spoofing IP: %s  (geo_anomaly=0 — purely ML detection)" % ip)

    # Stage A: 4 failed logins (rule threshold is failed_status_rate >= 0.5)
    info("")
    info("  Stage A: slow failed logins to raise failure rate without crossing threshold...")
    for i in range(4):
        try:
            SESSION.post(
                BASE_URL + "/login",
                json={"username": "sysadmin", "password": "attempt%d" % i},
                headers=headers,
                timeout=5,
            )
        except Exception:
            pass
        time.sleep(0.6)
    ok("    Stage A complete: 4 failed logins sent")

    # Stage B: 9 large file uploads to spike payload_size_variance
    info("")
    info("  Stage B: 9 large file uploads (spikes payload_size_variance feature)...")
    tmp = "stealth_large.pdf"
    for i in range(9):
        with open(tmp, "wb") as f:
            f.write(b"%PDF-1.4\n" + b"X" * (1024 * 1024 * 3))  # 3 MB
        try:
            with open(tmp, "rb") as f:
                SESSION.post(
                    BASE_URL + "/upload",
                    files={"file": ("stealth_%d.pdf" % i, f, "application/pdf")},
                    data={"paper_type": "simili_bw", "copies": "1"},
                    headers=headers,
                    timeout=10,
                )
        except Exception:
            pass
        sys.stdout.write(".")
        sys.stdout.flush()
    try:
        os.remove(tmp)
    except Exception:
        pass
    print()
    ok("    Stage B complete: 9 large uploads sent")

    # Stage C: Sustained volume at ~55 req/min (rule fires at 60)
    info("")
    info("  Stage C: request flood targeting ~55 req/min (rule fires at 60)...")
    end_time = time.time() + 30
    count    = 0
    while time.time() < end_time:
        try:
            SESSION.get(BASE_URL + "/", headers=headers, timeout=5)
            count += 1
        except Exception:
            pass
        time.sleep(1.09)  # ~55 req/min
    ok("    Stage C complete: %d requests sent at ~55 req/min" % count)

    info("")
    info("The combination of moderate failure rate, high payload variance, and")
    info("elevated (but sub-threshold) request volume creates a statistical")
    info("fingerprint the Isolation Forest recognises as anomalous.")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 56)
    print("  ACS Sentinel — Attack Simulator")
    print("  Target: http://127.0.0.1")
    print("=" * 56)
    print()
    print("  Detection method legend:")
    print("    [RULE]             -> Hybrid engine: rule threshold fired")
    print("    [ISOLATION FOREST] -> Hybrid engine: ML scored anomaly (no rule fired)")
    print()
    print("  IP legend:")
    print("    Malaysian IP (geo_anomaly=0) -> steps 1, 3, 4, 5, 6")
    print("    Foreign IP   (geo_anomaly=1) -> step 2 only")

    try:
        SESSION.get(BASE_URL, timeout=10)
        ok("Application reachable at http://127.0.0.1")
    except Exception as e:
        print("\n  [ERROR] Cannot reach http://127.0.0.1")
        print("  Make sure 'docker compose up -d' is running.")
        print("  Detail: " + str(e))
        return

    try:
        print("\n  Starting demo sequence in 3 seconds...")
        print("  Keep stream_processor logs visible to watch detections in real time.\n")
        time.sleep(3)

        normal_background_traffic(10)
        time.sleep(2)

        brute_force_login(80)
        time.sleep(5)

        low_severity_anomaly()
        time.sleep(5)

        medium_severity_anomaly(16)
        time.sleep(5)

        high_request_rate(20)
        time.sleep(5)

        combined_blitz()
        time.sleep(5)

        stealth_ml_attack()

        print("\n" + "=" * 56)
        print("  All attacks complete.")
        print("  Steps 1-5: check for [RULE] detections in sentinel logs.")
        print("  Step 6:    check for [ANOMALY] with method=isolation_forest.")
        print("=" * 56)

    except KeyboardInterrupt:
        print("\n\n  [STOPPED] Interrupted by user.")

    finally:
        print("\n  Verify DynamoDB blocked IPs:")
        print("    aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name blocked-ips")
        print("  Verify alerts:")
        print("    aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name alerts")


if __name__ == "__main__":
    main()
