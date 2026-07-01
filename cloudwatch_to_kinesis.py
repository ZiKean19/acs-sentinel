<<<<<<< HEAD
"""
cloudwatch_to_kinesis.py — Infrastructure Initialization Script
Creates CloudWatch Log Group, Kinesis Stream, and the Subscription Filter
that automatically pipes every log event from CloudWatch → Kinesis in real time.

Run ONCE before starting app.py and stream_processor.py.
Usage:
    python cloudwatch_to_kinesis.py
"""

import json
import time
import boto3
from botocore.exceptions import ClientError

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
LOCALSTACK_URL  = "http://localhost:4566"
AWS_REGION      = "us-east-1"
ACCOUNT_ID      = "000000000000"   # LocalStack default

LOG_GROUP       = "security-logs"
LOG_STREAM      = "app-events"
KINESIS_STREAM  = "security-stream"
SHARD_COUNT     = 1
FILTER_NAME     = "all-events-to-kinesis"
FILTER_PATTERN  = ""   # Empty string = forward ALL log events

AWS_KWARGS = dict(
    region_name=AWS_REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    endpoint_url=LOCALSTACK_URL,
)

# ─────────────────────────────────────────────
# Clients
# ─────────────────────────────────────────────
logs_client    = boto3.client("logs",    **AWS_KWARGS)
kinesis_client = boto3.client("kinesis", **AWS_KWARGS)
iam_client     = boto3.client("iam",     **AWS_KWARGS)


def _ok(msg):  print(f"  ✅  {msg}")
def _info(msg): print(f"  ℹ️   {msg}")
def _warn(msg): print(f"  ⚠️   {msg}")


# ─────────────────────────────────────────────
# Step 1: CloudWatch Log Group
# ─────────────────────────────────────────────
def create_log_group():
    print("\n[1/5] CloudWatch Log Group")
    try:
        logs_client.create_log_group(logGroupName=LOG_GROUP)
        _ok(f"Log group '{LOG_GROUP}' created.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            _info(f"Log group '{LOG_GROUP}' already exists — skipping.")
        else:
            raise


# ─────────────────────────────────────────────
# Step 2: CloudWatch Log Stream
# ─────────────────────────────────────────────
def create_log_stream():
    print("\n[2/5] CloudWatch Log Stream")
    try:
        logs_client.create_log_stream(logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
        _ok(f"Log stream '{LOG_STREAM}' created.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            _info(f"Log stream '{LOG_STREAM}' already exists — skipping.")
        else:
            raise


# ─────────────────────────────────────────────
# Step 3: Kinesis Data Stream
# ─────────────────────────────────────────────
def create_kinesis_stream():
    print("\n[3/5] Kinesis Data Stream")
    try:
        kinesis_client.create_stream(
            StreamName=KINESIS_STREAM,
            ShardCount=SHARD_COUNT,
        )
        _ok(f"Kinesis stream '{KINESIS_STREAM}' created with {SHARD_COUNT} shard(s).")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            _info(f"Kinesis stream '{KINESIS_STREAM}' already exists — skipping.")
        else:
            raise

    # Wait until stream is ACTIVE
    print("    Waiting for stream to become ACTIVE...")
    for _ in range(20):
        resp = kinesis_client.describe_stream(StreamName=KINESIS_STREAM)
        status = resp["StreamDescription"]["StreamStatus"]
        if status == "ACTIVE":
            _ok("Stream is ACTIVE.")
            return
        time.sleep(0.5)
    _warn("Stream did not reach ACTIVE state within timeout — proceeding anyway.")


# ─────────────────────────────────────────────
# Step 4: IAM Role for Subscription Filter
# ─────────────────────────────────────────────
def create_iam_role() -> str:
    """
    LocalStack accepts any role ARN for subscription filters.
    We create a minimal role so the ARN is real within LocalStack's IAM.
    """
    print("\n[4/5] IAM Role for Subscription Filter")
    role_name = "CloudWatchLogsToKinesisRole"
    role_arn  = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "logs.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    })

    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Description="Allows CloudWatch Logs to write to Kinesis.",
        )
        _ok(f"IAM role '{role_name}' created.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            _info(f"IAM role '{role_name}' already exists — skipping.")
        else:
            raise

    # Attach inline policy
    kinesis_arn = f"arn:aws:kinesis:{AWS_REGION}:{ACCOUNT_ID}:stream/{KINESIS_STREAM}"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
            "Resource": kinesis_arn,
        }]
    })
    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="KinesisPutPolicy",
            PolicyDocument=policy,
        )
        _ok("Inline Kinesis write policy attached.")
    except Exception as exc:
        _warn(f"Could not attach inline policy (LocalStack may not require it): {exc}")

    return role_arn


# ─────────────────────────────────────────────
# Step 5: Subscription Filter
# ─────────────────────────────────────────────
def create_subscription_filter(role_arn: str):
    """
    A Subscription Filter automatically forwards every matching log event
    from the CloudWatch log group to the Kinesis stream in real time.
    This is the bridge between app.py's logging and stream_processor.py.
    """
    print("\n[5/5] CloudWatch → Kinesis Subscription Filter")
    kinesis_arn = f"arn:aws:kinesis:{AWS_REGION}:{ACCOUNT_ID}:stream/{KINESIS_STREAM}"

    try:
        logs_client.put_subscription_filter(
            logGroupName=LOG_GROUP,
            filterName=FILTER_NAME,
            filterPattern=FILTER_PATTERN,   # "" means forward ALL events
            destinationArn=kinesis_arn,
            roleArn=role_arn,
            distribution="ByLogStream",
        )
        _ok(f"Subscription filter '{FILTER_NAME}' created.")
        _info(f"  Log Group : {LOG_GROUP}")
        _info(f"  → Kinesis : {kinesis_arn}")
        _info(f"  Filter    : (all events)")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("LimitExceededException", "InvalidParameterException"):
            _warn(f"Subscription filter may already exist or LocalStack limitation: {e}")
        else:
            raise


# ─────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────
def verify_setup():
    print("\n── Verification ──────────────────────────────")

    # CloudWatch
    groups = logs_client.describe_log_groups(logGroupNamePrefix=LOG_GROUP)
    names  = [g["logGroupName"] for g in groups["logGroups"]]
    status = "✅" if LOG_GROUP in names else "❌"
    print(f"  {status} CloudWatch log group  : {LOG_GROUP}")

    # Kinesis
    streams = kinesis_client.list_streams()["StreamNames"]
    status  = "✅" if KINESIS_STREAM in streams else "❌"
    print(f"  {status} Kinesis stream         : {KINESIS_STREAM}")

    # Subscription filter
    try:
        filters = logs_client.describe_subscription_filters(
            logGroupName=LOG_GROUP, filterNamePrefix=FILTER_NAME
        )["subscriptionFilters"]
        status = "✅" if filters else "⚠️ (not confirmed)"
    except Exception:
        status = "⚠️  (query failed — may still work)"
    print(f"  {status} Subscription filter    : {FILTER_NAME}")

    print("\n  Infrastructure ready. Start the pipeline:")
    print("    1. python app.py              ← generates logs")
    print("    2. python stream_processor.py ← consumes Kinesis")
    print("    3. streamlit run dashboard_v2.py")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 52)
    print("  ACS Infrastructure Initialization")
    print("  LocalStack endpoint:", LOCALSTACK_URL)
    print("=" * 52)

    create_log_group()
    create_log_stream()
    create_kinesis_stream()
    role_arn = create_iam_role()
    create_subscription_filter(role_arn)
    verify_setup()