#!/usr/bin/env bash
#
# deploy_presignup.sh — deploy the ACS Sentinel Cognito PreSignUp allowlist trigger
#
# Run from AWS CloudShell, in the same directory as cognito_pre_signup.py
# (Actions -> Upload file, then: bash deploy_presignup.sh)
#
# Safe to re-run: creates on first pass, updates on later ones.
#
set -euo pipefail

# ─── EDIT THESE ──────────────────────────────────────────────────────────────
ALLOWED_EMAILS="tengzikean@gmail.com"   # comma-separated exact addresses
ALLOWED_DOMAINS="apu.edu.my"            # comma-separated domains, or "" for none
# ─────────────────────────────────────────────────────────────────────────────

REGION="ap-southeast-1"
ACCOUNT="567017109835"
FUNC="acs-cognito-presignup"
ROLE="acs-presignup-role"
SRC="cognito_pre_signup.py"

[ -f "$SRC" ] || { echo "ERROR: $SRC not found. Upload it first (Actions -> Upload file)."; exit 1; }

echo "==> 1/6  Locating user pool"
POOL_ID=$(aws cognito-idp list-user-pools --max-results 60 --region "$REGION" \
  --query "UserPools[?contains(Name,'acs') || contains(Name,'sentinel')].Id" --output text)
if [ -z "$POOL_ID" ] || [ "$(echo "$POOL_ID" | wc -w)" -ne 1 ]; then
  echo "Could not uniquely identify the pool. Found: '$POOL_ID'"
  aws cognito-idp list-user-pools --max-results 60 --region "$REGION" \
    --query 'UserPools[].{Name:Name,Id:Id}' --output table
  echo "Set POOL_ID manually and re-run."; exit 1
fi
echo "    Pool: $POOL_ID"

echo "==> 2/6  Backing up user pool config (update-user-pool is a FULL REPLACE)"
aws cognito-idp describe-user-pool --user-pool-id "$POOL_ID" --region "$REGION" \
  > "userpool-backup-$(date +%Y%m%d-%H%M%S).json"
echo "    Saved. Keep this — it is your rollback."

echo "==> 3/6  Execution role (CloudWatch Logs only — this trigger needs nothing else)"
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  echo "    Created. Waiting 10s for IAM propagation..."
  sleep 10
else
  echo "    Already exists."
fi

echo "==> 4/6  Packaging"
rm -f presignup.zip && zip -qj presignup.zip "$SRC"

# JSON form is mandatory: the shorthand Variables={K=V,...} syntax splits on
# commas, which would mangle a multi-entry allowlist into bogus variables.
ENV_JSON=$(printf '{"Variables":{"ALLOWED_EMAILS":"%s","ALLOWED_DOMAINS":"%s"}}' \
  "$ALLOWED_EMAILS" "$ALLOWED_DOMAINS")

echo "==> 5/6  Deploying Lambda"
if aws lambda get-function --function-name "$FUNC" --region "$REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNC" --region "$REGION" \
    --zip-file fileb://presignup.zip >/dev/null
  aws lambda wait function-updated --function-name "$FUNC" --region "$REGION"
  aws lambda update-function-configuration --function-name "$FUNC" --region "$REGION" \
    --environment "$ENV_JSON" >/dev/null
  echo "    Updated."
else
  # Timeout 5s: Cognito aborts sync triggers at 5 seconds regardless.
  aws lambda create-function --function-name "$FUNC" --region "$REGION" \
    --runtime python3.12 --handler cognito_pre_signup.handler \
    --role "arn:aws:iam::${ACCOUNT}:role/${ROLE}" \
    --zip-file fileb://presignup.zip \
    --timeout 5 --memory-size 128 --environment "$ENV_JSON" >/dev/null
  echo "    Created."
fi
aws lambda wait function-updated --function-name "$FUNC" --region "$REGION"

echo "==> 6/6  Granting Cognito permission to invoke (BEFORE attaching the trigger)"
aws lambda add-permission --function-name "$FUNC" --region "$REGION" \
  --statement-id cognito-presignup-invoke \
  --action lambda:InvokeFunction \
  --principal cognito-idp.amazonaws.com \
  --source-arn "arn:aws:cognito-idp:${REGION}:${ACCOUNT}:userpool/${POOL_ID}" \
  >/dev/null 2>&1 && echo "    Granted." || echo "    Already granted."

FUNC_ARN=$(aws lambda get-function --function-name "$FUNC" --region "$REGION" \
  --query 'Configuration.FunctionArn' --output text)

cat <<EOF

────────────────────────────────────────────────────────────────────
Lambda deployed and invokable:
  $FUNC_ARN

Verify it denies before you attach it (see the test commands), then
attach the trigger in the CONSOLE, not the CLI:

  Cognito -> User pools -> $POOL_ID
    -> Extensions (or User pool properties) -> Add Lambda trigger
    -> Sign-up  ->  Pre sign-up  ->  $FUNC

The console merges the change. The CLI equivalent (update-user-pool)
replaces the entire pool configuration and resets anything you omit.
────────────────────────────────────────────────────────────────────
EOF
