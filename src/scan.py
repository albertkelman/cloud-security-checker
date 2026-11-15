"""Run every check and print a summary. Read-only."""

import json
from pathlib import Path

import boto3

from check_ec2 import run_sg_checks
from check_iam import run_iam_checks
from check_s3 import run_s3_checks
from common import HOME_REGION, PROFILE, apply_suppressions

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}


def main():
    session = boto3.Session(profile_name=PROFILE, region_name=HOME_REGION)
    account_id = session.client("sts").get_caller_identity()["Account"]

    print("Running checks:")
    findings = []
    findings.extend(run_s3_checks(session, account_id))
    findings.extend(run_iam_checks(session))
    findings.extend(run_sg_checks(session))

    apply_suppressions(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    errors = sum(1 for f in findings if f["status"] == "ERROR")
    suppressed = sum(1 for f in findings if f["status"] == "SUPPRESSED")

    print(f"\nFindings: {failed} FAIL, {errors} ERROR, {suppressed} SUPPRESSED")
    for f in findings:
        print(f"  [{f['severity']}] {f['status']} {f['check_id']} "
              f"{f['resource']} ({f['region']}): {f['message']}")
        if f["status"] == "SUPPRESSED":
            print(f"      Reason: {f['suppression_reason']}")

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "scan.findings.json"
    output_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"\nSaved to {output_file}")


if __name__ == "__main__":
    main()