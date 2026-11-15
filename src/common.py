"""Shared settings and helpers used by every check."""

import os
from datetime import datetime, timezone

# Locally we use the csc-dev profile.
# In Lambda, credentials come from the function's IAM role, so no profile is used.
RUNNING_IN_LAMBDA = "AWS_LAMBDA_FUNCTION_NAME" in os.environ
PROFILE = None if RUNNING_IN_LAMBDA else os.environ.get("AWS_PROFILE", "csc-dev")
HOME_REGION = "ap-southeast-2"

# Findings reviewed by a human and accepted, with a written reason.
# Key: (check_id, resource). They are still reported, but not counted as FAIL or ERROR.
SUPPRESSIONS = {
    ("ROOT_MFA", "root"): (
        "Root access is centrally managed through AWS Organizations; "
        "the root user has no long-term credentials "
        "(verified in IAM > Root access management)."
    ),
    ("SG_REGION_ACCESS", "regions"): (
        "This project is restricted to ap-southeast-2. AWS returned "
        "'explicit deny in a service control policy' for other regions, "
        "so resources cannot be created there either."
    ),
}

SUPPRESSIBLE_STATUSES = {"FAIL", "ERROR"}


def make_finding(check_id, resource, region, severity, status, message):
    """Build one finding in the standard format used by the whole project."""
    return {
        "check_id": check_id,
        "resource": resource,
        "region": region,
        "severity": severity,
        # FAIL = problem found, ERROR = could not check,
        # SUPPRESSED = reviewed and accepted (see SUPPRESSIONS)
        "status": status,
        "message": message,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def error_code(err):
    """Return the AWS error code from a botocore ClientError."""
    return err.response.get("Error", {}).get("Code", "Unknown")


def apply_suppressions(findings):
    """Mark reviewed findings as SUPPRESSED and keep their original status."""
    for finding in findings:
        reason = SUPPRESSIONS.get((finding["check_id"], finding["resource"]))
        if reason and finding["status"] in SUPPRESSIBLE_STATUSES:
            finding["original_status"] = finding["status"]
            finding["status"] = "SUPPRESSED"
            finding["suppression_reason"] = reason
    return findings