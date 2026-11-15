"""Core scan logic, shared by the local command line and the Lambda handler. Read-only."""

import json
from pathlib import Path

import boto3

from check_cloudtrail import run_cloudtrail_checks
from check_ec2 import run_sg_checks
from check_iam import run_iam_checks
from check_s3 import run_s3_checks
from common import HOME_REGION, PROFILE, apply_suppressions

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}


def create_session():
    """Local: uses the csc-dev profile. Lambda: uses the function's IAM role."""
    return boto3.Session(profile_name=PROFILE, region_name=HOME_REGION)


def run_all_checks(session):
    """Run every check, apply suppressions, and return findings sorted by severity."""
    account_id = session.client("sts").get_caller_identity()["Account"]

    findings = []
    findings.extend(run_s3_checks(session, account_id))
    findings.extend(run_iam_checks(session))
    findings.extend(run_sg_checks(session))
    findings.extend(run_cloudtrail_checks(session))

    apply_suppressions(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def summarize(findings):
    """Count findings by status."""
    return {
        "fail": sum(1 for f in findings if f["status"] == "FAIL"),
        "error": sum(1 for f in findings if f["status"] == "ERROR"),
        "suppressed": sum(1 for f in findings if f["status"] == "SUPPRESSED"),
    }


def print_report(findings, summary):
    """Print a human-readable report."""
    print(f"\nFindings: {summary['fail']} FAIL, {summary['error']} ERROR, "
          f"{summary['suppressed']} SUPPRESSED")
    for f in findings:
        print(f"  [{f['severity']}] {f['status']} {f['check_id']} "
              f"{f['resource']} ({f['region']}): {f['message']}")
        if f["status"] == "SUPPRESSED":
            print(f"      Reason: {f['suppression_reason']}")


def main():
    """Local entry point: run the scan and save the results to output/."""
    session = create_session()
    print("Running checks:")
    findings = run_all_checks(session)
    summary = summarize(findings)
    print_report(findings, summary)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "scan.findings.json"
    output_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"\nSaved to {output_file}")


if __name__ == "__main__":
    main()