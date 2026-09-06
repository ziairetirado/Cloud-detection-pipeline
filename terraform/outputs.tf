output "cloudtrail_arn" {
  value = aws_cloudtrail.this.arn
}

output "cloudtrail_log_group" {
  value = aws_cloudwatch_log_group.trail.name
}

output "sns_alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "detection_lambda_names" {
  value = { for k, v in aws_lambda_function.detection : k => v.function_name }
}

output "logs_insights_saved_queries" {
  value = [
    aws_cloudwatch_query_definition.console_logins.name,
    aws_cloudwatch_query_definition.iam_changes.name,
    aws_cloudwatch_query_definition.sg_changes.name,
  ]
}
