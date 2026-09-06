variable "aws_region" {
  description = "AWS region to deploy the pipeline into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to all resources"
  type        = string
  default     = "cloud-detect"
}

variable "alert_email" {
  description = "Email address to receive SNS security alerts"
  type        = string
}

variable "known_ip_ranges" {
  description = "CIDR ranges considered 'known' locations for console logins (office/VPN egress IPs). Logins from outside these ranges are treated as suspicious."
  type        = list(string)
  default     = []
}

variable "flag_foreign_logins" {
  description = "If true, enrich login IPs with GeoIP and flag logins from countries outside allowed_countries"
  type        = bool
  default     = true
}

variable "allowed_countries" {
  description = "ISO country codes considered normal for console logins when flag_foreign_logins is true"
  type        = list(string)
  default     = ["US"]
}

variable "cloudtrail_log_retention_days" {
  description = "Retention for the CloudWatch Logs group CloudTrail writes to"
  type        = number
  default     = 90
}
