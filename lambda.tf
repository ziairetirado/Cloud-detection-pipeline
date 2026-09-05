# Each detection is its own small Lambda so a bad rule/deploy only affects
# one detection, and IAM permissions stay scoped per-function.
#
# NOTE: run `../build.sh` before `terraform apply` — it copies lambda/common
# (alerting.py, geoip.py) into each function's build directory so the zip is
# self-contained. archive_file below zips the pre-built dirs.

locals {
  detections = {
    console_login = {
      dir         = "${path.module}/../build/detect_console_login"
      description = "Alerts on console logins from unknown IPs/countries or without MFA"
      event_pattern = jsonencode({
        source      = ["aws.signin"]
        detail-type = ["AWS Console Sign In via CloudTrail"]
        detail = {
          eventName = ["ConsoleLogin"]
        }
      })
      extra_env = {
        KNOWN_IP_RANGES     = join(",", var.known_ip_ranges)
        ALLOWED_COUNTRIES   = join(",", var.allowed_countries)
        FLAG_FOREIGN_LOGINS = tostring(var.flag_foreign_logins)
      }
    }
    iam_user_created = {
      dir         = "${path.module}/../build/detect_iam_user_created"
      description = "Alerts whenever a new IAM user is created"
      event_pattern = jsonencode({
        source      = ["aws.iam"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName   = ["CreateUser"]
        }
      })
      extra_env = {}
    }
    sg_open_internet = {
      dir         = "${path.module}/../build/detect_sg_open_internet"
      description = "Alerts when a security group ingress rule opens a port to 0.0.0.0/0 or ::/0"
      event_pattern = jsonencode({
        source      = ["aws.ec2"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress"]
        }
      })
      extra_env = {}
    }
  }
}

data "archive_file" "detection" {
  for_each    = local.detections
  type        = "zip"
  source_dir  = each.value.dir
  output_path = "${path.module}/../build/${each.key}.zip"
}

resource "aws_iam_role" "detection_lambda" {
  for_each = local.detections
  name     = "${local.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "detection_lambda" {
  for_each = local.detections
  name     = "${local.name}-${each.key}"
  role     = aws_iam_role.detection_lambda[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_lambda_function" "detection" {
  for_each         = local.detections
  function_name    = "${local.name}-${each.key}"
  description      = each.value.description
  role             = aws_iam_role.detection_lambda[each.key].arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 15
  memory_size      = 128
  filename         = data.archive_file.detection[each.key].output_path
  source_code_hash = data.archive_file.detection[each.key].output_base64sha256

  environment {
    variables = merge(
      { ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn },
      each.value.extra_env
    )
  }
}

resource "aws_cloudwatch_log_group" "detection_lambda" {
  for_each          = local.detections
  name              = "/aws/lambda/${aws_lambda_function.detection[each.key].function_name}"
  retention_in_days = 30
}

# --- EventBridge: CloudTrail management events land on the default bus
#     automatically once the trail exists; we just match on them. ---

resource "aws_cloudwatch_event_rule" "detection" {
  for_each      = local.detections
  name          = "${local.name}-${each.key}"
  description   = each.value.description
  event_pattern = each.value.event_pattern

  depends_on = [aws_cloudtrail.this]
}

resource "aws_cloudwatch_event_target" "detection" {
  for_each  = local.detections
  rule      = aws_cloudwatch_event_rule.detection[each.key].name
  target_id = "lambda"
  arn       = aws_lambda_function.detection[each.key].arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  for_each      = local.detections
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection[each.key].arn
}
