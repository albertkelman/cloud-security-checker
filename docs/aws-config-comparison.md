# Comparison with AWS native services

Tested on 2026-11-15 in ap-southeast-2, on the same account the scanner checks.

## Availability on this account

| Service | Result |
|---|---|
| AWS Security Hub | Blocked: explicit deny in an organization service control policy |
| AWS Config | Available. Enabled for about 10 minutes for this test, then removed |

This account is managed through an AWS Organization that restricts some native security
services. That is one practical reason to understand how these checks work.

## Check by check (clean account)

| Scanner check | AWS Config managed rule | Scanner | AWS Config | Same? |
|---|---|---|---|---|
| S3_ACCOUNT_BPA | s3-account-level-public-access-blocks-periodic | No finding | COMPLIANT | Yes |
| S3_BUCKET_BPA | s3-bucket-level-public-access-prohibited | No finding | COMPLIANT | Yes |
| S3_BUCKET_POLICY_PUBLIC, S3_BUCKET_ACL_PUBLIC | s3-bucket-public-read-prohibited | No finding | COMPLIANT | Yes |
| SG_OPEN_TO_INTERNET | restricted-ssh, restricted-common-ports | No finding | COMPLIANT | Yes |
| ROOT_ACCESS_KEYS | iam-root-access-key-check | No finding | COMPLIANT | Yes |
| ROOT_MFA | root-account-mfa-enabled | FAIL, suppressed with a written reason | INSUFFICIENT_DATA | Different |
| IAM_USER_NO_MFA | mfa-enabled-for-iam-console-access | 0 IAM users | INSUFFICIENT_DATA | Yes (nothing to check) |
| IAM_ACCESS_KEY_OLD | access-keys-rotated | 0 IAM users | INSUFFICIENT_DATA | Yes (nothing to check) |
| CLOUDTRAIL_NOT_ENABLED, CLOUDTRAIL_NOT_MULTI_REGION | multi-region-cloudtrail-enabled | No finding | COMPLIANT | Yes |
| CLOUDTRAIL_LOG_VALIDATION_OFF | cloud-trail-log-file-validation-enabled | No finding | COMPLIANT | Yes |

## Observations

1. **Root MFA.** The account uses centralized root access, so the root user has no
   long-term credentials. The scanner reads `AccountMFAEnabled = 0` from
   `GetAccountSummary` and reports a false positive, which I suppressed with a reason.
   AWS Config evaluated the rule successfully but returned INSUFFICIENT_DATA. Neither
   result means "safe": both mean "cannot be confirmed", and the scanner records why.

2. **Detection speed.** A security group with SSH open to 0.0.0.0/0 was created at
   22:37:40. AWS Config (change-triggered rule) reported NON_COMPLIANT within about
   1 to 3 minutes. The scanner runs daily at 07:00, so it would detect it up to about
   a day later (it detected it immediately when invoked by hand).

3. **Port coverage.** In AWS Config, SSH is covered by restricted-ssh, and
   restricted-common-ports did not flag port 22 with its default parameters.
   The scanner uses one check with its own port list (SSH, RDP, MySQL, PostgreSQL,
   SQL Server, Redis, MongoDB, all traffic) and one finding per security group.
   Two tools that both "check security groups" can still cover different ports.

4. **Rule catalog.** access-keys-rotated is documented as available in Sydney but was
   not shown in the console rule list. It was created with the AWS CLI
   (identifier ACCESS_KEYS_ROTATED) and became ACTIVE. The CLI does not fill in default
   parameters, so maxAccessKeyAge had to be set explicitly.

## Conclusion

| | AWS Config | This scanner |
|---|---|---|
| Detection | Near real time for change-triggered rules | Once a day (or on demand) |
| Coverage | Hundreds of managed rules, multi-account aggregation, remediation | A small set of checks |
| Cost | Charged per configuration item and per rule evaluation | Lambda, DynamoDB, and SNS usage for one run a day |
| Explanations | Compliance labels | Findings with written suppression reasons, new and resolved tracking |
| Availability | Can be restricted by an organization (Security Hub was) | Needs only read permissions |

For production, I would use AWS Config and Security Hub. I built this scanner to
understand how the checks work, and the comparison shows where the native services are
stronger (speed, coverage) and where my own logic helped (explaining the root MFA result).