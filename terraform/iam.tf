locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------- Lambda execution role ----------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name}-lambda-role"
  description        = "Execution role for the cloud-security-checker Lambda function"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

# Only the read actions the code calls, plus writing to its own log group,
# topic, and table. No permission to change or delete other resources.
data "aws_iam_policy_document" "scan" {
  statement {
    sid    = "ReadS3Configuration"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "s3:GetAccountPublicAccessBlock",
    ]
    # Account-level list and describe actions do not support resource-level permissions
    resources = ["*"]
  }

  statement {
    sid    = "ReadIamConfiguration"
    effect = "Allow"
    actions = [
      "iam:GetAccountSummary",
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ReadEc2Configuration"
    effect = "Allow"
    actions = [
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ReadCloudTrailConfiguration"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "WriteOwnLogsOnly"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "PublishToOwnTopicOnly"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid    = "TrackFindingsInOwnTableOnly"
    effect = "Allow"
    actions = [
      "dynamodb:Scan",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [aws_dynamodb_table.findings.arn]
  }
}

resource "aws_iam_policy" "scan" {
  name        = "${var.name}-scan-policy"
  description = "Read-only access to the configuration the scanner checks, plus writing its own logs"
  policy      = data.aws_iam_policy_document.scan.json
}

resource "aws_iam_role_policy_attachment" "lambda_scan" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.scan.arn
}

# ---------- EventBridge Scheduler role ----------

data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    # Only schedules in this account can use the role (confused deputy protection)
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name}-scheduler-role"
  path               = "/service-role/"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
}

data "aws_iam_policy_document" "scheduler_invoke" {
  statement {
    effect  = "Allow"
    actions = ["lambda:InvokeFunction"]
    resources = [
      aws_lambda_function.scanner.arn,
      "${aws_lambda_function.scanner.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name   = "invoke-scanner-lambda"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_invoke.json
}