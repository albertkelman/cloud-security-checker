# Project Notes: Mini Cloud Security Checker

## Session 0 - AWS account and security
- Created an AWS account (free plan, US$100 credits) through AWS Builder ID
- MFA (TOTP) and recovery email added to Builder ID
- Builder ID-based accounts do not show the classic root Security credentials page;
  Builder ID MFA protects sign-in
- No IAM users or access keys
- Budget: monthly-cost-budget, US$10
- Project is locked to ap-southeast-2 (Sydney); settings.aws.com does not show the
  project yet. Will retry switching to ap-southeast-1 before Session 4.

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
- Wrote src/scan_s3.py: checks 4 layers (account BPA, bucket BPA, bucket policy
  status, bucket ACL). Status FAIL = problem found, ERROR = could not check.
- Error: MissingDependencyException when boto3 reads `aws login` credentials
- Fix: pip install "botocore[crt]"
- First real finding: account-level Block Public Access was not configured (MEDIUM)
- Confirmed in the S3 console (all settings off), enabled "Block all public access"
- Re-ran the scanner: 0 findings