# Project Notes: Mini Cloud Security Checker

## Session 0 - AWS account and security (2026-11-15)
- Created an AWS account (free plan, US$100 credits) through AWS Builder ID
- MFA (TOTP) and recovery email added to Builder ID
- Builder ID-based accounts do not show the classic root Security credentials page;
  Builder ID MFA protects sign-in
- No IAM users or access keys
- Budget: monthly-cost-budget, US$10
- Project is locked to ap-southeast-2 (Sydney); settings.aws.com does not show the
  project yet. Will retry switching to ap-southeast-1 before Session 4.

## Session 1 - Local tools and repo (2026-11-15)
- Installed Python 3.13 and AWS CLI v2.40 with winget
- CLI sign-in: aws login --profile csc-dev (temporary credentials, AccountFullAccessRole)
- Declined AWS MCP integration for AI agents (role is too broad)
- Created private repo cloud-security-checker