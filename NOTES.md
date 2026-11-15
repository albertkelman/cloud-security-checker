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