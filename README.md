# ACS Sentinel — Decoupled Architecture

## Folder Structure

```
acs-sentinel/
│
├── acs/                        ← THE ACS PRODUCT (your main project)
│   ├── sentinel/               ← Detection engine + dashboard API
│   │   ├── main.py             ← Entry point: runs detection + serves dashboard
│   │   ├── stream_processor.py ← Tails Nginx log, extracts features
│   │   ├── anomaly_detector_engine.py  ← Isolation Forest ML engine
│   │   ├── mitigation_handler.py       ← IP blocking + Telegram alerts
│   │   ├── evaluator.py        ← Performance evaluation (for FYP report)
│   │   └── Dockerfile
│   ├── nginx/                  ← Nginx reverse proxy (enforces blocklist)
│   │   ├── nginx.conf
│   │   ├── blocked_ips.conf    ← Written by ACS automatically
│   │   └── Dockerfile
│   └── dashboard/              ← React security dashboard
│       └── src/
│
├── target-app/                 ← SIMULATED BUSINESS APP (not part of ACS)
│   ├── app.py                  ← Only responsibility: send logs to CloudWatch
│   └── templates/
│
├── docker-compose.yml          ← Starts everything
├── init-aws.sh                 ← Auto-creates all AWS resources
└── attack_simulator.py         ← Simulates attack traffic for testing
```

---

## The Key Separation

**ACS Sentinel** does:
- Reads Nginx access logs (shared volume)
- Detects anomalies with Isolation Forest + rules
- Blocks malicious IPs in Nginx + DynamoDB
- Sends Telegram alerts
- Serves the security dashboard at `http://localhost:8080`

**Your application** does:
- Runs its business logic
- Sends logs to CloudWatch (one function, ~10 lines)
- Nothing else. Zero ACS code inside it.

---

## How to Integrate ACS with ANY Application

Your app only needs this one function (shown in Python, but works in any language):

```python
def push_log(event_type, extra):
    logs_client.put_log_events(
        logGroupName="security-logs",
        logStreamName="app-events",
        logEvents=[{
            "timestamp": int(time.time() * 1000),
            "message": json.dumps({"event_type": event_type, "ip": client_ip, **extra})
        }]
    )
```

For Node.js, Java, or any other language, use the AWS SDK equivalent.
That is the complete integration. ACS handles everything else.

---

## How to Run (3 terminals)

**Terminal 1 — Start Docker stack**
```bash
docker compose up --build
```
Wait for: `ACS Sentinel — Detection Engine Starting`

**Terminal 2 — Start React dashboard**
```bash
cd acs/dashboard
npm install
npm run dev
```
Open: `http://localhost:5173`  |  Login: `admin / sentinel`

**Terminal 3 — Run attack simulation**
```bash
python attack_simulator.py
```

**Stop everything**
```bash
docker compose down
```

---

## AWS Deployment Plan

When ready to deploy to real AWS, the changes are:

| Local (Docker)            | AWS Production                        |
|---------------------------|---------------------------------------|
| LocalStack                | Real AWS account                      |
| Nginx log tail loop       | Lambda triggered by Kinesis           |
| Flask dashboard (port 8080)| API Gateway + Lambda                 |
| DynamoDB (LocalStack)     | DynamoDB (real)                       |
| Blocked IPs conf file     | AWS WAF IP Set / API Gateway policy   |
| React on localhost:5173   | AWS Amplify hosting                   |

The target app does not change at all during AWS migration.
Only the ACS infrastructure changes.

---

## Optional — Telegram Alerts

Fill in your `.env` file:
```
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```
Then restart: `docker compose down && docker compose up --build`
