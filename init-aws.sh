#!/bin/bash
# init-aws.sh — Auto-provisions all LocalStack AWS resources on startup.
# Runs once via LocalStack's ready.d hook. No manual terminal commands required.

echo "=== Initializing LocalStack AWS Resources ==="

REGION="us-east-1"
ACCOUNT_ID="000000000000"

create_dynamo_table() {
  local table_name=$1
  local key_name=$2
  echo "Creating DynamoDB table: ${table_name}..."
  awslocal dynamodb create-table \
    --table-name "${table_name}" \
    --attribute-definitions AttributeName="${key_name}",AttributeType=S \
    --key-schema AttributeName="${key_name}",KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"
}

# 1. DynamoDB Tables
create_dynamo_table "blocked-ips"   "ip"
create_dynamo_table "alerts"        "alert_id"
create_dynamo_table "log-stream"    "log_id"
create_dynamo_table "print-orders"  "order_id"

# 2. Kinesis Stream
echo "Creating Kinesis stream: security-stream..."
awslocal kinesis create-stream \
  --stream-name security-stream \
  --shard-count 1 \
  --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

# 3. CloudWatch Log Group and Streams
echo "Creating CloudWatch log group: security-logs..."
awslocal logs create-log-group \
  --log-group-name security-logs \
  --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

awslocal logs create-log-stream \
  --log-group-name security-logs \
  --log-stream-name app-events \
  --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

awslocal logs create-log-stream \
  --log-group-name security-logs \
  --log-stream-name mitigations \
  --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

# 4. IAM Role for CloudWatch -> Kinesis subscription filter
echo "Creating IAM Role: CloudWatchLogsToKinesisRole..."
awslocal iam create-role \
  --role-name CloudWatchLogsToKinesisRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

# 5. CloudWatch Subscription Filter: logs -> Kinesis
echo "Creating subscription filter..."
awslocal logs put-subscription-filter \
  --log-group-name security-logs \
  --filter-name all-events-to-kinesis \
  --filter-pattern "" \
  --destination-arn "arn:aws:kinesis:${REGION}:${ACCOUNT_ID}:stream/security-stream" \
  --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/CloudWatchLogsToKinesisRole" \
  --region "${REGION}" 2>/dev/null || echo "  (already exists — skipping)"

echo "=== LocalStack AWS Resources Ready ==="
