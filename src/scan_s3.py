"""
Session 2: local S3 public access check.

Read-only: this script only calls Get* and List* APIs.
It never changes anything in the AWS account.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

PROFILE = os.environ.get("AWS_PROFILE", "csc-dev")
HOME_REGION = "ap-southeast-2"

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
BPA_KEYS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def make_finding(check_id, resource, region, severity, status, message):
    """Build one finding in the standard format used by the whole project."""
    return {
        "check_id": check_id,
        "resource": resource,
        "region": region,
        "severity": severity,
        "status": status,  # FAIL = problem found, ERROR = could not check
        "message": message,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def error_code(err):
    return err.response.get("Error", {}).get("Code", "Unknown")


def check_bpa_config(config):
    """Return the names of Block Public Access settings that are turned off."""
    return [key for key in BPA_KEYS if not config.get(key)]


def check_account_bpa(session, account_id):
    """Layer 1: account-level Block Public Access."""
    check_id = "S3_ACCOUNT_BPA"
    s3control = session.client("s3control", region_name=HOME_REGION)
    try:
        response = s3control.get_public_access_block(AccountId=account_id)
    except ClientError as err:
        if error_code(err) == "NoSuchPublicAccessBlockConfiguration":
            return [make_finding(check_id, "account", "global", "MEDIUM", "FAIL",
                                 "Account-level Block Public Access is not configured")]
        return [make_finding(check_id, "account", "global", "UNKNOWN", "ERROR",
                             f"Could not check: {error_code(err)}")]

    off = check_bpa_config(response["PublicAccessBlockConfiguration"])
    if off:
        return [make_finding(check_id, "account", "global", "MEDIUM", "FAIL",
                             f"Account-level Block Public Access settings off: {', '.join(off)}")]
    return []


def check_bucket(session, bucket, region):
    """Layers 2-4: bucket-level BPA, bucket policy, and ACL."""
    findings = []
    s3 = session.client("s3", region_name=region)

    # Layer 2: bucket-level Block Public Access
    try:
        response = s3.get_public_access_block(Bucket=bucket)
        off = check_bpa_config(response["PublicAccessBlockConfiguration"])
        if off:
            findings.append(make_finding("S3_BUCKET_BPA", bucket, region, "MEDIUM", "FAIL",
                                         f"Bucket Block Public Access settings off: {', '.join(off)}"))
    except ClientError as err:
        if error_code(err) == "NoSuchPublicAccessBlockConfiguration":
            findings.append(make_finding("S3_BUCKET_BPA", bucket, region, "MEDIUM", "FAIL",
                                         "Bucket Block Public Access is not configured"))
        else:
            findings.append(make_finding("S3_BUCKET_BPA", bucket, region, "UNKNOWN", "ERROR",
                                         f"Could not check: {error_code(err)}"))

    # Layer 3: bucket policy evaluated as public by AWS
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]
        if status.get("IsPublic"):
            findings.append(make_finding("S3_BUCKET_POLICY_PUBLIC", bucket, region, "HIGH", "FAIL",
                                         "Bucket policy is evaluated as public by AWS"))
    except ClientError as err:
        if error_code(err) != "NoSuchBucketPolicy":
            findings.append(make_finding("S3_BUCKET_POLICY_PUBLIC", bucket, region, "UNKNOWN", "ERROR",
                                         f"Could not check: {error_code(err)}"))

    # Layer 4: ACL grants to everyone or to any AWS user
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        public_grants = [
            grant for grant in acl.get("Grants", [])
            if grant.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES
        ]
        if public_grants:
            groups = sorted({g["Grantee"]["URI"].rsplit("/", 1)[-1] for g in public_grants})
            findings.append(make_finding("S3_BUCKET_ACL_PUBLIC", bucket, region, "HIGH", "FAIL",
                                         f"ACL grants access to {', '.join(groups)}"))
    except ClientError as err:
        findings.append(make_finding("S3_BUCKET_ACL_PUBLIC", bucket, region, "UNKNOWN", "ERROR",
                                     f"Could not check: {error_code(err)}"))

    return findings


def list_buckets(session):
    """Return (name, region) for every bucket, using pagination."""
    s3 = session.client("s3", region_name=HOME_REGION)
    buckets = []
    for page in s3.get_paginator("list_buckets").paginate():
        for bucket in page.get("Buckets", []):
            name = bucket["Name"]
            region = bucket.get("BucketRegion")
            if not region:
                location = s3.get_bucket_location(Bucket=name)["LocationConstraint"]
                region = location or "us-east-1"
            buckets.append((name, region))
    return buckets


def main():
    session = boto3.Session(profile_name=PROFILE, region_name=HOME_REGION)
    account_id = session.client("sts").get_caller_identity()["Account"]

    findings = check_account_bpa(session, account_id)
    buckets = list_buckets(session)
    for name, region in buckets:
        findings.extend(check_bucket(session, name, region))

    print(f"Checked: account-level BPA and {len(buckets)} bucket(s)")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['status']} {f['check_id']} "
              f"{f['resource']} ({f['region']}): {f['message']}")

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "s3.findings.json"
    output_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    main()