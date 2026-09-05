"""Detects creation of new IAM users. New IAM principals are rare in a
steady-state account, so any creation is treated as noteworthy and worth a
human glance -- this is one of the highest-value low-effort detections for
catching both insider misuse and a compromised admin credential establishing
persistence.
"""
from alerting import publish_alert

# Roles/users that are allowed to create IAM users without alerting, e.g. your
# CI/CD or IaC pipeline role. Leave empty to alert on every creation.
import os

SUPPRESS_FOR_PRINCIPALS = {
    p.strip() for p in os.environ.get("SUPPRESS_FOR_PRINCIPALS", "").split(",") if p.strip()
}


def handler(event, context):
    detail = event.get("detail", {})

    if detail.get("eventName") != "CreateUser":
        return {"skipped": True}

    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    if actor in SUPPRESS_FOR_PRINCIPALS:
        return {"skipped": True, "reason": "actor is an allow-listed automation principal"}

    new_user = detail.get("requestParameters", {}).get("userName", "unknown")
    source_ip = detail.get("sourceIPAddress", "unknown")

    publish_alert(
        rule_name="new-iam-user-created",
        severity="HIGH",
        summary=f"New IAM user '{new_user}' created by {actor}",
        details={
            "new_user": new_user,
            "created_by": actor,
            "source_ip": source_ip,
            "event_time": detail.get("eventTime"),
        },
    )
    return {"alerted": True}
