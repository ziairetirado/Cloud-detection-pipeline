"""Shared helper for publishing consistently formatted alerts to SNS."""
import json
import os
from datetime import datetime, timezone

import boto3

sns = boto3.client("sns")
TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")


def publish_alert(rule_name: str, severity: str, summary: str, details: dict) -> None:
    """Publish a security finding to the shared SNS alert topic.

    severity: one of LOW / MEDIUM / HIGH / CRITICAL
    """
    message = {
        "rule": rule_name,
        "severity": severity,
        "summary": summary,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }

    print(json.dumps({"alert": message}))  # always land in CloudWatch Logs too

    if not TOPIC_ARN:
        return

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[{severity}] {rule_name}",
        Message=json.dumps(message, indent=2, default=str),
        MessageAttributes={
            "severity": {"DataType": "String", "StringValue": severity}
        },
    )
