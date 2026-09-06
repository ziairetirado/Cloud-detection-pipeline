# --- S3 bucket for long-term, durable CloudTrail log storage ---

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "${local.name}-cloudtrail-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# --- CloudWatch Logs group CloudTrail streams into, so we get near-real-time
#     delivery for Logs Insights hunting queries (S3 delivery lags ~5-15 min) ---

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.name}"
  retention_in_days = var.cloudtrail_log_retention_days
}

resource "aws_iam_role" "trail_to_cwl" {
  name = "${local.name}-cloudtrail-to-cwl"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  name = "${local.name}-cloudtrail-to-cwl"
  role = aws_iam_role.trail_to_cwl.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

# --- The trail itself: multi-region, management + a few key data events,
#     log file validation on so tampering is detectable ---

resource "aws_cloudtrail" "this" {
  name                          = local.name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cwl.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

# --- Saved Logs Insights queries for manual threat hunting ---

resource "aws_cloudwatch_query_definition" "console_logins" {
  name = "${local.name}/console-logins-by-ip"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string = <<-EOT
    fields @timestamp, userIdentity.userName, sourceIPAddress, additionalEventData.MFAUsed, responseElements.ConsoleLogin
    | filter eventName = "ConsoleLogin"
    | sort @timestamp desc
  EOT
}

resource "aws_cloudwatch_query_definition" "iam_changes" {
  name = "${local.name}/iam-write-events"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, eventName, requestParameters.userName
    | filter eventSource = "iam.amazonaws.com" and eventName like /(CreateUser|CreateAccessKey|AttachUserPolicy|CreateLoginProfile)/
    | sort @timestamp desc
  EOT
}

resource "aws_cloudwatch_query_definition" "sg_changes" {
  name = "${local.name}/security-group-opens"
  log_group_names = [aws_cloudwatch_log_group.trail.name]
  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, requestParameters.groupId, requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp
    | filter eventName = "AuthorizeSecurityGroupIngress"
    | sort @timestamp desc
  EOT
}
