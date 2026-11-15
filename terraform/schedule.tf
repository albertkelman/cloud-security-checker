resource "aws_scheduler_schedule" "daily" {
  name        = "${var.name}-daily"
  group_name  = "default"
  description = "Runs the cloud-security-checker Lambda once a day"

  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone
  state                        = "ENABLED"
  action_after_completion      = "NONE"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.scanner.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }
  }
}