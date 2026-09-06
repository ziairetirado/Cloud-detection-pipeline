"""Detects AWS Console logins from IP ranges / countries that aren't on the
known-good list, and any login where MFA was not used.

Triggered by an EventBridge rule matching CloudTrail's ConsoleLogin event,
delivered on the default event bus.
"""
import ipaddress
import os

from alerting import publish_alert
from geoip import lookup_country

KNOWN_CIDRS = [c.strip() for c in os.environ.get("KNOWN_IP_RANGES", "").split(",") if c.strip()]
ALLOWED_COUNTRIES = {c.strip().upper() for c in os.environ.get("ALLOWED_COUNTRIES", "US").split(",") if c.strip()}
FLAG_FOREIGN_LOGINS = os.environ.get("FLAG_FOREIGN_LOGINS", "true").lower() == "true"


def _ip_is_known(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in KNOWN_CIDRS)


def handler(event, context):
    detail = event.get("detail", {})

    if detail.get("eventName") != "ConsoleLogin":
        return {"skipped": True}

    # Failed logins matter too, but we only alert on success here to keep
    # signal-to-noise reasonable; wire a second lower-severity rule for
    # repeated failures if you want brute-force detection.
    if detail.get("responseElements", {}).get("ConsoleLogin") != "Success":
        return {"skipped": True, "reason": "login not successful"}

    ip = detail.get("sourceIPAddress", "")
    user = detail.get("userIdentity", {}).get("arn", "unknown")
    mfa_used = detail.get("additionalEventData", {}).get("MFAUsed", "No")

    reasons = []

    known_ip = _ip_is_known(ip)
    if not known_ip:
        reasons.append("source IP not in known/allowed CIDR ranges")

    country = None
    if FLAG_FOREIGN_LOGINS and not known_ip:
        country = lookup_country(ip)
        if country and country not in ALLOWED_COUNTRIES:
            reasons.append(f"login originated from unexpected country: {country}")

    if mfa_used != "Yes":
        reasons.append("MFA was not used for this login")

    if not reasons:
        return {"skipped": True, "reason": "login matches known-good baseline"}

    severity = "HIGH" if (not known_ip and mfa_used != "Yes") else "MEDIUM"

    publish_alert(
        rule_name="console-login-unknown-location",
        severity=severity,
        summary=f"Console login for {user} from {ip} flagged: {'; '.join(reasons)}",
        details={
            "principal": user,
            "source_ip": ip,
            "country": country,
            "mfa_used": mfa_used,
            "reasons": reasons,
            "event_time": detail.get("eventTime"),
        },
    )
    return {"alerted": True}
