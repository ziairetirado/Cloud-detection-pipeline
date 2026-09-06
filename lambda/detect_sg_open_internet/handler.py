"""Detects security group ingress rules that open a port to the entire
internet (0.0.0.0/0 or ::/0). Flags sensitive ports (SSH, RDP, DB engines) as
CRITICAL and everything else as MEDIUM, since "open to the world" is not
automatically catastrophic (e.g. 443 on a public web tier) but frequently is.
"""
from alerting import publish_alert

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 5900}

OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"


def _iter_permissions(request_params: dict):
    """CloudTrail nests ingress rules under ipPermissions.items[]."""
    perms = request_params.get("ipPermissions", {}).get("items", [])
    for perm in perms:
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        cidrs = [r.get("cidrIp") for r in perm.get("ipRanges", {}).get("items", [])]
        cidrs += [r.get("cidrIpv6") for r in perm.get("ipv6Ranges", {}).get("items", [])]
        yield from_port, to_port, [c for c in cidrs if c]


def handler(event, context):
    detail = event.get("detail", {})

    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return {"skipped": True}

    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId", "unknown")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    findings = []
    for from_port, to_port, cidrs in _iter_permissions(request_params):
        opened_to_world = OPEN_V4 in cidrs or OPEN_V6 in cidrs
        if not opened_to_world:
            continue

        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
        touches_sensitive_port = any(
            p is not None and from_port is not None and to_port is not None and from_port <= p <= to_port
            for p in SENSITIVE_PORTS
        )
        findings.append(
            {
                "port_range": port_range,
                "sensitive": touches_sensitive_port,
            }
        )

    if not findings:
        return {"skipped": True, "reason": "no rule opened to 0.0.0.0/0 or ::/0"}

    severity = "CRITICAL" if any(f["sensitive"] for f in findings) else "MEDIUM"

    publish_alert(
        rule_name="security-group-open-to-internet",
        severity=severity,
        summary=f"Security group {group_id} opened to the internet by {actor}",
        details={
            "group_id": group_id,
            "modified_by": actor,
            "opened_ports": findings,
            "event_time": detail.get("eventTime"),
        },
    )
    return {"alerted": True}
