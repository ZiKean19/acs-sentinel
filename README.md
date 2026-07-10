# ACS Sentinel — Automated Cloud Security Sentinel

An ML-based intrusion detection and automated response system for Malaysian SMEs, built entirely on AWS serverless infrastructure. ACS Sentinel monitors web application traffic, detects anomalies using a hybrid rule-based and machine-learning engine, and automatically blocks malicious IP addresses at the firewall layer — with real-time alerting and human-in-the-loop override.

This project was developed as a Final Year Project (APU, TP070370).

---

## Overview

ACS Sentinel protects a target web application by analysing its traffic in near real time. When an attack is detected, the system records an alert, blocks the offending IP via AWS WAF, and notifies the administrator through Telegram — where the block can be reviewed and reversed with a single tap. A secured React dashboard provides live visibility into alerts, blocked IPs, and system logs.

The entire system is serverless: there are no servers or containers to manage, idle compute cost is near zero, and the architecture scales automatically.

---

## Architecture

```
                          ┌─────────────────────────┐
   Attacker / User  ─────▶│  Target App (Lambda)     │
                          │  "Bumi SME Portal"       │
                          │  + AWS WAF (IP blocking) │
                          └───────────┬──────────────┘
                                      │ structured JSON logs
                                      ▼
                          ┌─────────────────────────┐
                          │  CloudWatch Logs         │
                          │  (subscription filter)   │
                          └───────────┬──────────────┘
                                      │
                                      ▼
                          ┌─────────────────────────┐
                          │  Detection Lambda        │
                          │  • Rule engine           │
                          │  • Isolation Forest (ML) │
                          │  • MaxMind GeoLite2       │
                          └───────────┬──────────────┘
                                      │ writes
                    ┌─────────────────┼──────────────────┐
                    ▼                 ▼                  ▼
             ┌────────────┐   ┌──────────────┐   ┌──────────────┐
             │ DynamoDB   │   │ AWS WAF IPSet│   │ Telegram Bot │
             │ alerts /   │   │ (auto-block) │   │ (alert +     │
             │ blocked-ips│   │              │   │  unblock)    │
             └─────┬──────┘   └──────────────┘   └──────────────┘
                   │
                   ▼
         ┌───────────────────┐      ┌─────────────────────────┐
         │ Dashboard Lambda  │◀─────│ API Gateway + Cognito    │
         │ (REST API)        │      │ (JWT authorizer)         │
         └───────────────────┘      └───────────┬─────────────┘
                                                 ▼
                                     ┌─────────────────────────┐
                                     │ React Dashboard          │
                                     │ (AWS Amplify Hosting)    │
                                     └─────────────────────────┘
```

All resources are deployed in **ap-southeast-1 (Singapore)**.

---

## Key Features

- **Hybrid detection** — a deterministic rule engine catches obvious attacks (floods, brute force) while an Isolation Forest model catches subtle, low-and-slow anomalies that fixed rules miss.
- **Four-tier severity** — detections are classified LOW / MEDIUM / HIGH / CRITICAL, with severity-proportional block durations (TTL).
- **Real geolocation** — uses the MaxMind GeoLite2 country database to flag non-Malaysian traffic, rather than naive IP-prefix matching.
- **Automated response** — malicious IPs are added to an AWS WAF IP Set automatically and blocked at the edge (HTTP 403) before requests reach the application.
- **Human-in-the-loop** — every alert is delivered to Telegram with an inline "Unblock" button, and the dashboard offers manual override.
- **Secured dashboard** — the admin dashboard authenticates via Amazon Cognito (JWT), and the API is protected by an API Gateway Cognito authorizer.

---

## AWS Services Used

| Service | Role |
|---|---|
| AWS Lambda | Detection engine, dashboard API, target application |
| Amazon DynamoDB | Alerts, blocked IPs, log stream, per-IP rolling windows (with TTL) |
| Amazon S3 | ML model (`.pkl`) and GeoLite2 database storage |
| Amazon CloudWatch Logs | Log ingestion + subscription filter to Detection Lambda |
| Amazon API Gateway | Dashboard REST API (HTTP API) and target app (REST API) |
| Amazon Cognito | Admin authentication (User Pool + JWT authorizer) |
| AWS WAF | IP-based blocking enforcement on the target app |
| AWS Amplify | Dashboard hosting (CI/CD from GitHub) |
| AWS IAM | Least-privilege roles for Lambda execution |

---

## Repository Structure

```
acs-sentinel/
├── acs/dashboard/           React + TypeScript admin dashboard (Vite)
├── lambdas/
│   ├── detection_lambda/    Anomaly detection (rules + Isolation Forest + geo)
│   ├── dashboard_lambda/    REST API handler for the dashboard
│   └── target_lambda/       "Bumi SME Portal" target application
├── attack_simulator.py      Traffic / attack generation for testing
├── archive/                 Legacy LocalStack/Docker prototype (superseded)
└── README.md
```

---

## Machine Learning Approach

The detection model uses an **Isolation Forest**, an unsupervised anomaly-detection algorithm well suited to identifying outliers without labelled attack data. It is trained on synthetically generated traffic representing normal and attack profiles across three behavioural features:

- `total_requests` — request volume per IP in a 60-second window
- `failed_status_rate` — proportion of HTTP error responses
- `payload_size_variance` — variability in request sizes

The `contamination` parameter and decision threshold are tuned to balance detection sensitivity against false positives. The rule engine and ML model are complementary: rules provide fast, explainable detection of known attack patterns, while the Isolation Forest generalises to novel or evasive traffic.

*Note: synthetic training data is a documented prototype simplification. Validation against a labelled benchmark dataset (e.g. CICIDS2017) is identified as future work.*

---

## Local Development (Dashboard)

The dashboard is a Vite + React + TypeScript app.

```bash
cd acs/dashboard
npm install
npm run dev
```

Create a `.env` file in `acs/dashboard/` (never committed) with:

```
VITE_API_URL=<your API Gateway URL>
VITE_COGNITO_USER_POOL_ID=<your Cognito user pool id>
VITE_COGNITO_CLIENT_ID=<your Cognito app client id>
```

---

## Deployment

- **Lambda functions** are packaged and deployed via the AWS CLI (see `lambdas/`). The detection function uses a scikit-learn Lambda layer and loads its model + GeoLite2 database from S3 at runtime.
- **Dashboard** is deployed to AWS Amplify Hosting, which builds automatically from this repository's `main` branch (base directory `acs/dashboard`).

---

## Future Enhancements

- **Kinesis Data Streams** as a scalable ingestion buffer between CloudWatch and the Detection Lambda, providing shock-absorbing buffering during high-volume attack floods, event replay for fault recovery, and multi-consumer fan-out. *(The Detection Lambda is already written to accept both direct CloudWatch and Kinesis event shapes, so this is a drop-in addition.)*
- **Model validation** against labelled benchmark datasets (CICIDS2017, NSL-KDD).
- **Secure Remote Password (SRP)** authentication flow for Cognito, replacing the current `USER_PASSWORD_AUTH` flow.
- **Multi-channel alerting** via Amazon SNS (email/SMS) alongside Telegram.

---

## Notes on Security

- Secrets (API tokens, credentials) are stored in environment variables and never committed to the repository.
- IAM roles follow least-privilege principles scoped to the specific resources each Lambda requires.
- The admin dashboard and its API are protected by Cognito authentication.

---

## Acknowledgements

Geolocation data provided by [MaxMind](https://www.maxmind.com) GeoLite2. This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.

---

*Developed for academic purposes as a Final Year Project.*
