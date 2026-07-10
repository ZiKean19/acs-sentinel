#!/bin/bash
# deploy_detection_lambda.sh
# Run this from your acs-sentinel project root (adjust LAMBDA_DIR if needed).
# Requires: Docker Desktop running (to build layer matching Lambda's Linux runtime),
# AWS CLI configured, region ap-southeast-1.

set -e

REGION="ap-southeast-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/acs-sentinel-lambda-role"
LAMBDA_DIR="./lambdas/detection_lambda"
LAYER_DIR="./lambda-layer-build"
FUNCTION_NAME="acs-detection-lambda"
LAYER_NAME="acs-sklearn-layer"

echo ">> Account: $ACCOUNT_ID | Role: $ROLE_ARN"

# ---------- 1. Build the dependency layer (numpy + scikit-learn + boto3 extras) ----------
echo ">> Building dependency layer (this can take a few minutes)..."
rm -rf "$LAYER_DIR"
mkdir -p "$LAYER_DIR/python"

docker run --rm -v "$(pwd)/$LAYER_DIR":/out public.ecr.aws/lambda/python:3.12 \
  pip install scikit-learn numpy -t /out/python --no-cache-dir

cd "$LAYER_DIR"
zip -r ../sklearn-layer.zip python > /dev/null
cd -

echo ">> Publishing layer..."
LAYER_VERSION_ARN=$(aws lambda publish-layer-version \
  --layer-name "$LAYER_NAME" \
  --zip-file fileb://sklearn-layer.zip \
  --compatible-runtimes python3.12 \
  --region "$REGION" \
  --query 'LayerVersionArn' --output text)

echo ">> Layer published: $LAYER_VERSION_ARN"

# ---------- 2. Package the function code ----------
echo ">> Zipping function code..."
cd "$LAMBDA_DIR"
rm -f ../detection_function.zip
zip ../detection_function.zip lambda_function.py anomaly_detector_engine.py > /dev/null
cd -

# ---------- 3. Create or update the Lambda function ----------
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" > /dev/null 2>&1; then
  echo ">> Function exists, updating code..."
  aws lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file fileb://lambdas/detection_function.zip \
    --region "$REGION"
else
  echo ">> Creating function..."
  aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.12 \
    --role "$ROLE_ARN" \
    --handler lambda_function.handler \
    --zip-file fileb://lambdas/detection_function.zip \
    --timeout 30 \
    --memory-size 512 \
    --layers "$LAYER_VERSION_ARN" \
    --environment "Variables={MODEL_BUCKET=acs-sentinel-models-teng,BLOCKLIST_TABLE=blocked-ips,ALERTS_TABLE=alerts,LOGSTREAM_TABLE=log-stream,WINDOW_TABLE=ip-windows,TELEGRAM_BOT_TOKEN=,TELEGRAM_CHAT_ID=}" \
    --region "$REGION"
fi

echo ">> Done. Function: $FUNCTION_NAME"
