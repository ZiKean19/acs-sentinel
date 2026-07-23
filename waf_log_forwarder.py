"""
waf_log_forwarder.py — us-east-1

Why this exists
---------------
CloudFront can only be fronted by a web ACL whose scope is CLOUDFRONT, and AWS
requires those resources — and therefore their logs — to live in us-east-1.
A CloudWatch Logs subscription filter can only invoke a Lambda in its OWN
region, so the us-east-1 WAF log group cannot call the detection function in
ap-southeast-1 directly.

This function is the one hop that closes that gap. It receives the subscription
event and passes the payload through unchanged to the detection Lambda, which
already understands the {"awslogs": {"data": ...}} shape. Nothing is decoded,
inspected or reshaped here — keeping it dumb means there is only one place
where log parsing can be wrong.

Invocation is asynchronous (InvocationType="Event"): the detection Lambda does
model scoring, DynamoDB writes and a Telegram call, none of which the log
pipeline should wait on. If the detection function is briefly unavailable,
Lambda's own async retry handles it.

Deploy
------
    runtime  : python3.12
    handler  : waf_log_forwarder.handler
    region   : us-east-1
    timeout  : 10s   (a pass-through needs no more)
    memory   : 128MB
    env      : TARGET_FUNCTION_ARN = arn of acs-detection-lambda
    IAM      : lambda:InvokeFunction on that ARN, plus basic execution role
"""

import os
import json
import boto3
from botocore.config import Config

TARGET_FUNCTION_ARN = os.environ.get("TARGET_FUNCTION_ARN", "")
TARGET_REGION = os.environ.get("TARGET_REGION", "ap-southeast-1")

# Short timeouts and no retries: this is a fire-and-forget hop on a hot path.
# A slow invoke would pile up behind the log stream rather than shed load.
_lambda = boto3.client(
    "lambda",
    region_name=TARGET_REGION,
    config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 2}),
)


def handler(event, context):
    if not TARGET_FUNCTION_ARN:
        print("[ERROR] TARGET_FUNCTION_ARN is not set — nothing to forward to.")
        return {"statusCode": 500, "forwarded": 0}

    if "awslogs" not in event:
        print(f"[WARN] Unexpected event shape, keys={list(event.keys())} — ignoring.")
        return {"statusCode": 200, "forwarded": 0}

    try:
        _lambda.invoke(
            FunctionName=TARGET_FUNCTION_ARN,
            InvocationType="Event",          # async: do not block the log pipeline
            Payload=json.dumps(event).encode(),
        )
        return {"statusCode": 200, "forwarded": 1}
    except Exception as exc:
        # Loud, because a silent failure here looks exactly like "no traffic":
        # the dashboard simply stops updating with no other symptom.
        print(f"[ERROR] Could not forward WAF logs to {TARGET_FUNCTION_ARN}: {exc}")
        raise
