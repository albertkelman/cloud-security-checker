"""AWS Lambda entry point. Read-only, except for publishing the report to SNS."""

import json

from notify import send_report
from scan import create_session, print_report, run_all_checks, summarize


def lambda_handler(event, context):
    """Called by AWS Lambda. Runs the scan, logs the results, and emails the report."""
    session = create_session()
    print("Running checks:")
    findings = run_all_checks(session)
    summary = summarize(findings)
    print_report(findings, summary)

    # One JSON line with the full result, easy to search in CloudWatch Logs
    print(json.dumps({"summary": summary, "findings": findings}))

    # If publishing fails, the error makes this run fail, so it is visible as a Lambda error
    send_report(session, findings, summary)
    return summary