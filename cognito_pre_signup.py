"""
cognito_pre_signup.py — ACS Sentinel Cognito PreSignUp trigger

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

Deploy as its own Lambda and attach:
    aws cognito-idp update-user-pool \
      --user-pool-id <POOL_ID> --region ap-southeast-1 \
      --lambda-config PreSignUp=<THIS_LAMBDA_ARN>

Environment variables:
    ALLOWED_EMAILS   comma-separated exact addresses
                     e.g. "tengzikean@gmail.com,tp070370@mail.apu.edu.my"
    ALLOWED_DOMAINS  comma-separated domains, "@" optional
                     e.g. "apu.edu.my"  (an SME would use its Workspace domain)

At least one must be non-empty, otherwise every sign-up is denied (fail closed).
"""

import os


def _split_env(name: str) -> set:
    return {v.strip().lower().lstrip("@") for v in os.environ.get(name, "").split(",") if v.strip()}


ALLOWED_EMAILS = _split_env("ALLOWED_EMAILS")
ALLOWED_DOMAINS = _split_env("ALLOWED_DOMAINS")


class UnauthorisedSignUp(Exception):
    """Message surfaces to the user on the Cognito sign-in page."""


def handler(event, context):
    source = event.get("triggerSource", "")
    attrs = event.get("request", {}).get("userAttributes", {})
    email = (attrs.get("email") or "").strip().lower()

    # Fail closed. An empty allowlist is a misconfiguration, not permission to
    # let everyone in — the whole point of this trigger is to be the gate.
    if not ALLOWED_EMAILS and not ALLOWED_DOMAINS:
        print("[DENY] allowlist is empty — refusing all sign-ups. Set ALLOWED_EMAILS/ALLOWED_DOMAINS.")
        raise UnauthorisedSignUp("ACS Sentinel is not accepting new accounts.")

    if not email:
        print(f"[DENY] identity provider returned no email claim (triggerSource={source})")
        raise UnauthorisedSignUp("An email address is required to access ACS Sentinel.")

    domain = email.rsplit("@", 1)[-1]
    if email not in ALLOWED_EMAILS and domain not in ALLOWED_DOMAINS:
        print(f"[DENY] {email} is not on the allowlist (triggerSource={source})")
        raise UnauthorisedSignUp(
            "This account is not authorised to access ACS Sentinel. Contact your administrator."
        )

    # Federated identities have already been verified by the upstream provider,
    # so re-verifying the address would ask the operator to confirm something
    # Google has already proven they control.
    if source == "PreSignUp_ExternalProvider":
        event["response"]["autoConfirmUser"] = True
        event["response"]["autoVerifyEmail"] = True

    print(f"[ALLOW] {email} (triggerSource={source})")
    return event
