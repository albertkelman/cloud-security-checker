"""Root account and IAM user checks. Read-only (plus generating the credential report)."""

import csv
import io
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from common import error_code, make_finding

ACCESS_KEY_MAX_AGE_DAYS = 90


def check_root_account(iam):
    """Root MFA and root access keys, from the IAM account summary."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError as err:
        return [make_finding("ROOT_ACCOUNT", "root", "global", "UNKNOWN", "ERROR",
                             f"Could not check: {error_code(err)}")]

    findings = []
    if summary.get("AccountAccessKeysPresent", 0) == 1:
        findings.append(make_finding("ROOT_ACCESS_KEYS", "root", "global", "HIGH", "FAIL",
                                     "Root account has access keys"))
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(make_finding("ROOT_MFA", "root", "global", "HIGH", "FAIL",
                                     "Root account does not have MFA enabled"))
    return findings


def get_credential_report(iam):
    """Generate the IAM credential report and return its rows as dictionaries."""
    for _ in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(2)
    else:
        raise TimeoutError("Credential report was not ready in time")

    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def is_older_than(timestamp, days):
    """True if an ISO timestamp from the credential report is older than `days`."""
    if not timestamp or timestamp in ("N/A", "not_supported"):
        return False
    rotated = datetime.fromisoformat(timestamp)
    return datetime.now(timezone.utc) - rotated > timedelta(days=days)


def check_iam_users(iam):
    """IAM users without MFA, and old active access keys."""
    try:
        rows = get_credential_report(iam)
    except (ClientError, TimeoutError) as err:
        reason = error_code(err) if isinstance(err, ClientError) else str(err)
        return [make_finding("IAM_CREDENTIAL_REPORT", "account", "global", "UNKNOWN", "ERROR",
                             f"Could not check: {reason}")], 0

    findings = []
    users = [row for row in rows if row["user"] != "<root_account>"]
    for row in users:
        user = row["user"]

        if row["password_enabled"] == "true" and row["mfa_active"] == "false":
            findings.append(make_finding("IAM_USER_NO_MFA", user, "global", "MEDIUM", "FAIL",
                                         "User can sign in to the console without MFA"))

        for key in ("1", "2"):
            active = row[f"access_key_{key}_active"] == "true"
            rotated = row[f"access_key_{key}_last_rotated"]
            if active and is_older_than(rotated, ACCESS_KEY_MAX_AGE_DAYS):
                findings.append(make_finding(
                    "IAM_ACCESS_KEY_OLD", user, "global", "MEDIUM", "FAIL",
                    f"Access key {key} is older than {ACCESS_KEY_MAX_AGE_DAYS} days"))

    return findings, len(users)


def run_iam_checks(session):
    """Run all root and IAM checks and return the findings."""
    iam = session.client("iam")
    findings = check_root_account(iam)
    user_findings, user_count = check_iam_users(iam)
    findings.extend(user_findings)
    print(f"  IAM: root account and {user_count} IAM user(s) checked")
    return findings