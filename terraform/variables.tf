variable "region" {
  description = "AWS region for every resource"
  type        = string
  default     = "ap-southeast-2"
}

variable "name" {
  description = "Base name for every resource"
  type        = string
  default     = "cloud-security-checker"
}

variable "alert_email" {
  description = "Email address that receives scan reports and alarms"
  type        = string
}

variable "schedule_expression" {
  description = "When the scanner runs (EventBridge Scheduler syntax)"
  type        = string
  default     = "cron(0 7 * * ? *)"
}

variable "schedule_timezone" {
  description = "Time zone for the schedule"
  type        = string
  default     = "Asia/Jakarta"
}