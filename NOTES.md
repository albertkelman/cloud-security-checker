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