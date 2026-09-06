# Architecture

<img width="1195" height="896" alt="Cloud detection pipeline diagram" src="https://github.com/user-attachments/assets/13e48b8f-f150-483f-afc3-e968ab70c0ea" />

## Why this shape

- **CloudTrail → S3 *and* CloudWatch Logs.** S3 is the durable, tamper-evident
  record of truth (log file validation is on, bucket is private + encrypted).
  CloudWatch Logs is the "SIEM" query surface — Logs Insights gives ad-hoc
  hunting across all three saved queries without standing up OpenSearch/Splunk.
- **EventBridge as the detection trigger**, not a Lambda polling CloudWatch
  Logs. CloudTrail management events publish to the default event bus in
  near-real-time, so pattern-matching there means detections fire in seconds,
  not on a batch schedule.
- **One Lambda per detection.** Keeps IAM permissions minimal per function,
  keeps blast radius of a bad deploy to one rule, and makes it trivial to add
  a fourth/fifth detection later without touching the others.
- **SNS as the alert sink.** Cheap, and trivially swapped for a Slack webhook
  or PagerDuty integration via an additional subscription — the alert payload
  is already structured JSON with a `severity` field for routing.

## Detection logic summary

| Detection | Trigger | Flags | Severity |
|---|---|---|---|
| Console login, unknown location | `ConsoleLogin` success | source IP outside allow-listed CIDRs; optionally GeoIP country outside allow-list; MFA not used | MEDIUM / HIGH |
| New IAM user created | `CreateUser` | any creation not from an allow-listed automation principal | HIGH |
| Security group opened to internet | `AuthorizeSecurityGroupIngress` | rule includes `0.0.0.0/0` or `::/0` | MEDIUM, or CRITICAL if the port is SSH/RDP/a DB engine |

## Known limitations / what I'd add next

- GeoIP uses ip-api.com's free tier for demo purposes — no SLA, rate-limited.
  Production version should use MaxMind GeoLite2 (or a paid feed) and cache
  results in DynamoDB.
- No baseline learning — "known" IPs are a static CIDR list today. A v2 could
  track per-user login history in DynamoDB and flag genuinely *new* source IPs
  per user rather than a single shared allow-list.
- No suppression/dedup window — a noisy actor triggers one alert per event.
  Worth adding an EventBridge-to-SQS buffer with a short aggregation window.
- Console-login failures (brute force) aren't covered yet — same event source,
  just a different `responseElements.ConsoleLogin` value and a counting rule.
