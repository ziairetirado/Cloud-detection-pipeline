# Cloud Threat Detection Pipeline

A serverless AWS detection pipeline that turns raw CloudTrail activity into
actionable security alerts — no third-party SIEM license or always-on
infrastructure required. Built as a portfolio project to demonstrate
detection engineering: identifying the right signal, writing the rule logic,
and wiring it into a pipeline that actually fires in near-real-time.

## The problem

Every AWS account generates a firehose of API activity through CloudTrail,
but logging activity isn't the same as *detecting* threats in it. Most small
teams either pay for a full SIEM they don't need yet, or turn on CloudTrail
and never look at it again until an incident forces them to. This project
closes that gap cheaply: CloudTrail → EventBridge → Lambda → SNS, with three
concrete detections that map to common real-world attack patterns.

## What it detects

1. **Console logins from unknown locations** — flags logins from source IPs
   outside a known-good CIDR allow-list, optionally cross-checked against a
   GeoIP country allow-list, and separately flags any login where MFA wasn't
   used.
2. **New IAM users** — alerts on every `CreateUser` call not made by an
   allow-listed automation principal (e.g. your CI/CD role). New IAM
   principals are rare in steady state, so this catches both persistence
   after a credential compromise and unauthorized account creation.
3. **Security groups opened to the internet** — inspects
   `AuthorizeSecurityGroupIngress` calls for `0.0.0.0/0` / `::/0` rules, and
   escalates to CRITICAL when the exposed port is SSH, RDP, or a common
   database engine.

Full architecture and rule-by-rule reasoning: [`docs/architecture.md`](docs/architecture.md).

## Why serverless instead of a hosted SIEM

I deliberately skipped standing up OpenSearch/Splunk/Wazuh for this version.
CloudTrail already delivers management events to EventBridge's default bus in
near-real-time, so pattern-matching there and firing Lambda gets alerts out in
seconds with zero idle infrastructure cost — the whole pipeline scales to
zero when there's no activity. CloudWatch Logs Insights covers the "SIEM"
need for ad-hoc hunting via three saved queries (console logins, IAM writes,
security group changes) without running a cluster. The trade-off, and what
I'd revisit for a larger environment, is in [Known limitations](docs/architecture.md#known-limitations--what-id-add-next).

## Stack

- **Terraform** for all infrastructure (CloudTrail, S3, CloudWatch Logs,
  EventBridge rules, Lambda, IAM, SNS)
- **Python 3.12** Lambda handlers, one per detection
- **EventBridge** pattern matching on specific CloudTrail event names
- **SNS** for alert delivery (email out of the box; swap in a Slack/PagerDuty
  subscription for real use)

## Repo layout

```
cloud-detection-pipeline/
├── terraform/              # all infra as code
│   ├── main.tf
│   ├── cloudtrail.tf        # trail, S3, CloudWatch Logs, saved Insights queries
│   ├── lambda.tf            # detection Lambdas, IAM, EventBridge rules
│   ├── sns.tf                # alert topic + email subscription
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── lambda/
│   ├── common/               # shared helpers (alerting, GeoIP lookup)
│   ├── detect_console_login/
│   ├── detect_iam_user_created/
│   └── detect_sg_open_internet/
├── build.sh                 # bundles lambda/common/ into each function's zip
└── docs/architecture.md     # diagram + detection logic table + limitations
```

## Deploying it

```bash
# 1. Bundle the shared helper code into each function's build dir
./build.sh

# 2. Configure your alert email + known-good IP ranges
cd terraform
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# 3. Deploy
terraform init
terraform apply
```

After applying, confirm the SNS email subscription (check your inbox), then
trigger a test finding — e.g. create a throwaway IAM user, or add a `0.0.0.0/0`
ingress rule to a security group — and you should get an alert within seconds.

## Sample alert payload

```json
{
  "rule": "security-group-open-to-internet",
  "severity": "CRITICAL",
  "summary": "Security group sg-0123456789abcdef0 opened to the internet by arn:aws:iam::111111111111:user/jdoe",
  "detected_at": "2026-09-05T14:02:11.483921+00:00",
  "details": {
    "group_id": "sg-0123456789abcdef0",
    "modified_by": "arn:aws:iam::111111111111:user/jdoe",
    "opened_ports": [{"port_range": "22", "sensitive": true}],
    "event_time": "2026-09-05T14:02:09Z"
  }
}
```

## Skills demonstrated

Detection engineering (choosing signal, writing rule logic against real
CloudTrail event shapes), AWS security services (CloudTrail, IAM, EventBridge,
Lambda, SNS), infrastructure as code (Terraform), least-privilege IAM design
(per-function scoped roles), and secure-by-default resource config (private +
encrypted S3, log file validation).
