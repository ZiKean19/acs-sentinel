"""
cognito_pre_signup.py — ACS Sentinel Cognito PreSignUp trigger (DynamoDB-backed)

Federation authenticates. It does not authorise.

Enabling Google sign-in on a Cognito user pool makes the pool self-service by
default: any Google account can create a dashboard user, and the API Gateway
JWT authoriser will happily accept the resulting token because it was issued by
the correct pool. For an ordinary web app that is the intended behaviour. For a
security console that exposes an UNBLOCK control it is a privilege-escalation
path — a blocked attacker signs in with Gmail and lifts their own block.

Cognito invokes this trigger BEFORE creating any user, including federated ones
(triggerSource = "PreSignUp_ExternalProvider"). Raising an exception aborts
account creation, so an unapproved identity never becomes a user at all. The
allowlist is therefore the authorisation boundary; Google only ever proves
*who* someone is, never *that they may enter*.

The allowlist used to live in the ALLOWED_EMAILS / ALLOWED_DOMAINS environment
variables. It now lives in a DynamoDB table so it can be managed at runtime from
the dashboard's admin-only Users page — no redeploy to add or remove an
operator. The env vars are still honoured as a fallback/seed, so an empty table
does not lock everyone out during migration.

Deploy as its own Lambda and attach:
    aws cognito-idp update-user-pool \
      --user-pool-id <POOL_ID> --region ap-southeast-1 \
      --lambda-config PreSignUp=<THIS_LAMBDA_ARN>

Table schema (allowed-users):
    email (S, HASH)   exact lowercased address, OR a "@domain" entry (see below)
    role  (S)         "admin" | "operator" | "domain"   (informational here;
                      the Users page uses it. "domain" marks a whole-domain
                      allow entry whose `email` is like "@apu.edu.my".)

Environment variables:
    ALLOWLIST_TABLE   DynamoDB table name (default "allowed-users")
    ALLOWED_EMAILS    optional comma-separated fallback (migration seed)
    ALLOWED_DOMAINS   optional comma-separated fallback, "@" optional

The allowlist is empty ONLY if both the table and the fallback are empty; in
that case every sign-up is denied (fail closed).
"""

import os

import boto3
from botocore.exceptions import ClientError

ALLOWLIST_TABLE = os.environ.get("ALLOWLIST_TABLE", "allowed-users")

_dynamo = boto3.client("dynamodb")


def _split_env(name: str) -> set:
    return {v.strip().lower().lstrip("@") for v in os.environ.get(name, "").split(",") if v.strip()}


# Env-var fallback. Kept so a not-yet-populated table cannot lock everyone out.
_FALLBACK_EMAILS = _split_env("ALLOWED_EMAILS")
_FALLBACK_DOMAINS = _split_env("ALLOWED_DOMAINS")


class UnauthorisedSignUp(Exception):
    """Message surfaces to the user on the Cognito sign-in page."""


def _email_allowed(email: str) -> bool:
    """
    True if `email` is on the allowlist. Checks, in order:
      1. exact email row in the table
      2. a whole-domain row in the table, stored as "@<domain>"
      3. the env-var fallback (exact email or domain)

    A read failure fails CLOSED — a transient DynamoDB fault must not become an
    open door. It is logged loudly so the cause is visible in CloudWatch.
    """
    domain = email.rsplit("@", 1)[-1]

    try:
        exact = _dynamo.get_item(
            TableName=ALLOWLIST_TABLE,
            Key={"email": {"S": email}},
            ConsistentRead=True,
        )
        if "Item" in exact:
            return True

        dom = _dynamo.get_item(
            TableName=ALLOWLIST_TABLE,
            Key={"email": {"S": f"@{domain}"}},
            ConsistentRead=True,
        )
        if "Item" in dom:
            return True
    except ClientError as exc:
        # Fail closed on infrastructure faults, then fall through to the env
        # fallback so a mis-named table during migration is survivable.
        print(f"[WARN] allowlist table read failed ({exc.response.get('Error', {}).get('Code')}) "
              f"— falling back to env vars.")

    return email in _FALLBACK_EMAILS or domain in _FALLBACK_DOMAINS


def handler(event, context):
    source = event.get("triggerSource", "")
    attrs = event.get("request", {}).get("userAttributes", {})
    email = (attrs.get("email") or "").strip().lower()

    if not email:
        print(f"[DENY] identity provider returned no email claim (triggerSource={source})")
        raise UnauthorisedSignUp("An email address is required to access ACS Sentinel")

    if not _email_allowed(email):
        print(f"[DENY] {email} is not on the allowlist (triggerSource={source})")
        raise UnauthorisedSignUp(
            "This account is not authorised to access ACS Sentinel. Contact your administrator"
        )

    # Federated identities have already been verified by the upstream provider,
    # so re-verifying the address would ask the operator to confirm something
    # Google has already proven they control.
    if source == "PreSignUp_ExternalProvider":
        event["response"]["autoConfirmUser"] = True
        event["response"]["autoVerifyEmail"] = True

    print(f"[ALLOW] {email} (triggerSource={source})")
    return event
