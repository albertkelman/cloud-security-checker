resource "aws_sns_topic" "alerts" {
  name = "scanner-alerts"
}

# The email address must confirm the subscription once (link sent by AWS)
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}