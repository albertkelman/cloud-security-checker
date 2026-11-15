# Zip every Python file in src/ (boto3 is already included in the Lambda runtime)
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../build/terraform-function.zip"
  excludes    = ["__pycache__"]
}

resource "aws_lambda_function" "scanner" {
  function_name = var.name
  role          = aws_iam_role.lambda.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 120

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy_attachment.lambda_scan,
  ]
}