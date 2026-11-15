# Created before the Lambda function so logs are kept for 14 days, not forever
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 14
}