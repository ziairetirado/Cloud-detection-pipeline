"""Best-effort GeoIP lookup used to flag console logins from unexpected countries.

Uses ip-api.com's free tier (no key, 45 req/min limit). This is a portfolio /
demo-grade integration — for production, swap in MaxMind GeoLite2 or a paid
provider with an SLA, and cache results (e.g. in DynamoDB) to avoid rate limits.
"""
import ipaddress
import json
import urllib.request

_TIMEOUT_SECONDS = 2


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup_country(ip: str) -> str | None:
    """Return the ISO country code for an IP, or None if it can't be determined."""
    if not ip or is_private_ip(ip):
        return None

    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data.get("countryCode")
    except Exception as exc:  # network issues shouldn't crash the detection
        print(f"geoip lookup failed for {ip}: {exc}")
    return None
