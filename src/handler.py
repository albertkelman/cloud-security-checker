"""AWS Lambda entry point. Read-only."""

import json

from scan import create_session, print_report, run_all_checks, summarize


def lambda_handler(event, context):
    """Called by AWS Lambda. Runs the scan and writes the results to the logs."""
    session = create_session()
    print("Running checks:")
    findings = run_all_checks(session)
    summary = summarize(findings)
    print_report(findings, summary)

    # One JSON line with the full result, easy to search in CloudWatch Logs
    print(json.dumps({"summary": summary, "findings": findings}))
    return summary