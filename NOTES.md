# Project Notes: Mini Cloud Security Checker

## Session 0 - AWS account and security
- Created an AWS account (free plan, US$100 credits) through AWS Builder ID
- MFA (TOTP) and recovery email added to Builder ID
- Builder ID-based accounts do not show the classic root Security credentials page;
  Builder ID MFA protects sign-in
- No IAM users or access keys
- Budget: monthly-cost-budget, US$10
- Region: ap-southeast-2 (Sydney). The project is restricted to this region by an
  organization SCP, so the whole project stays in Sydney.

## Session 1 - Local tools and repo
- Installed Python 3.13 and AWS CLI v2.40 with winget
- CLI sign-in: aws login --profile csc-dev (temporary credentials, AccountFullAccessRole)
- Sign-in to ap-southeast-1 was rejected because the project is locked to ap-southeast-2
- Declined AWS MCP integration for AI agents (role is too broad)
- Created private repo cloud-security-checker with .gitignore (venv, secrets,
  Terraform state, scanner output)
- PowerShell blocked venv activation; fixed with
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
- pip freeze with ">" wrote UTF-16 in PowerShell 5.1; switched to
  Out-File -Encoding utf8

## Session 2 - S3 public access check
- Wrote the S3 check: 4 layers (account BPA, bucket BPA, bucket policy status,
  bucket ACL). Status FAIL = problem found, ERROR = could not check.
- Error: MissingDependencyException when boto3 reads `aws login` credentials
- Fix: pip install "botocore[crt]"
- First real finding: account-level Block Public Access was not configured (MEDIUM)
- Confirmed in the S3 console (all settings off), enabled "Block all public access"
- Re-ran the scanner: 0 findings

## Session 3 - Root, IAM, security group, and CloudTrail checks
- Refactored into common.py, check_s3.py, check_iam.py, check_ec2.py,
  check_cloudtrail.py, and scan.py
- IAM checks: ROOT_ACCESS_KEYS, ROOT_MFA, IAM_USER_NO_MFA, IAM_ACCESS_KEY_OLD
  (IAM users come from the IAM credential report)
- Finding: ROOT_MFA (HIGH). Investigated: IAM > Root access management shows only
  "privileged actions" (centralized root access via AWS Organizations).
  The root user has no long-term credentials.
  Conclusion: false positive. Added SUPPRESSIONS with a written reason instead of
  deleting the check. Suppressed findings are still reported.
- Security group check: sensitive ports (SSH, RDP, databases, Redis, MongoDB, or all
  traffic) open to 0.0.0.0/0 or ::/0, across all enabled regions
- 16 of 17 regions denied. Verified with the AWS CLI: "explicit deny in a service
  control policy". Suppressed SG_REGION_ACCESS with a written reason.
  Limitation: the suppression key does not include the region list.
- Bug: apply_suppressions only handled FAIL, so the ERROR finding stayed visible.
  Fixed to allow FAIL and ERROR, and kept the original status in "original_status".
- Finding: CLOUDTRAIL_NOT_ENABLED (MEDIUM). Fixed by creating
  management-events-trail (multi-region, management events only, no KMS,
  no CloudWatch Logs, no Insights).
- The new CloudTrail log bucket passed all 4 S3 checks.
- Added CLOUDTRAIL_LOG_VALIDATION_OFF check. It detected that quick create left log
  file validation disabled (LOW). Enabled it and re-ran: 0 FAIL, 0 ERROR,
  2 SUPPRESSED.

  ## Session 4 - Running the scanner in AWS Lambda
- Split the code: scan.py (shared logic + local entry point) and handler.py
  (Lambda entry point). common.py detects Lambda through AWS_LAMBDA_FUNCTION_NAME
  and uses the function role instead of the csc-dev profile.
- Created log group /aws/lambda/cloud-security-checker with 14-day retention
  (Lambda would otherwise create one that keeps logs forever)
- Created cloud-security-checker-scan-policy: only the read actions the code calls,
  plus CreateLogStream/PutLogEvents on its own log group. No write or data access.
  Resource "*" is needed for account-level actions such as s3:ListAllMyBuckets.
- Created cloud-security-checker-lambda-role (trusted by lambda.amazonaws.com) with
  only that policy. Did not attach AWSLambdaBasicExecutionRole.
- Created Lambda function cloud-security-checker: Python, arm64, 256 MB,
  120 s timeout, handler handler.lambda_handler, no function URL, no VPC.
  Code uploaded as build/function.zip (boto3 is included in the runtime).
- First run in Lambda: 0 FAIL, 0 ERROR, 2 SUPPRESSED. No AccessDenied errors,
  so the custom policy covers every API call.
  Duration ~21 s, max memory 124 MB.

  ## Session 5 - Email reports and daily schedule
- Created SNS topic scanner-alerts and confirmed an email subscription
- Added sns:Publish to the policy, limited to the scanner-alerts topic ARN
  (new policy version set as default)
- Added notify.py: plain-text report grouped by FAIL, ERROR, and SUPPRESSED.
  Subject says OK or ACTION NEEDED. The topic ARN comes from the ALERT_TOPIC_ARN
  environment variable, so the code does not contain the account ID.
- The report is sent after every scan, even with 0 findings, so a missing email
  means the scanner is broken
- If publishing fails, the Lambda run fails instead of hiding the error
- Deployed with the AWS CLI (update-function-code, update-function-configuration)
  and invoked: StatusCode 200, report received by email
- Created EventBridge Scheduler schedule cloud-security-checker-daily:
  cron(0 7 * * ? *) in Asia/Jakarta (07:00 WIB), flexible window off,
  retry 2 times within 1 hour, no DLQ
- Execution role cloud-security-checker-scheduler-role (created by the console, renamed):
  only lambda:InvokeFunction on the cloud-security-checker function.
  Trust policy allows only scheduler.amazonaws.com with aws:SourceAccount
  (protection against the confused deputy problem).
- The Lambda resource-based policy stays empty: Scheduler invokes through its role.
- Tested with a one-time schedule (cloud-security-checker-test) set to delete itself
  after running. Report email arrived at the scheduled time without a manual invoke.

  ## Session 6 - Finding history and alarms
- Created DynamoDB table scanner-findings (on-demand, partition key finding_key =
  check_id#resource#region)
- Added dynamodb:Scan, PutItem, UpdateItem on that table only. No DeleteItem,
  so the scanner cannot erase its own history.
- Added store.py: compares each scan with open findings in the table and returns
  new, still open, and resolved findings. Resolved rows are kept (is_open = false,
  resolved_at). Suppressed findings are not tracked.
- Used ExpressionAttributeNames because "status" is a DynamoDB reserved word
- Email now starts with "Changes since the last scan" and the subject adds "N NEW"
- If the history update fails, the report is still emailed, then the run fails
  so the error alarm fires
- Lambda environment variables: ALERT_TOPIC_ARN and FINDINGS_TABLE.
  Note: --environment replaces all variables, so both must be passed together.
- Full cycle test with a test security group (SSH open to 0.0.0.0/0, no instances):
  scan 1: 1 NEW, scan 2: still open (no NEW), deleted the group, scan 3: 1 resolved.
  DynamoDB row: is_open false, first_seen and resolved_at recorded.