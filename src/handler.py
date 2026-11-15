"""AWS Lambda entry point. Reads configuration; writes only logs, its findings table, and its SNS topic."""

import json

from notify import send_report
from scan import create_session, print_report, run_all_checks, summarize
from store import track_findings


def lambda_handler(event, context):
    """Called by AWS Lambda. Runs the scan, updates the history, and emails the report."""
    session = create_session()
    print("Running checks:")
    findings = run_all_checks(session)
    summary = summarize(findings)
    print_report(findings, summary)

    # One JSON line with the full result, easy to search in CloudWatch Logs
    print(json.dumps({"summary": summary, "findings": findings}))

    # If the history fails, still send the report, then fail the run so the alarm fires
    history, history_error = None, None
    try:
        history = track_findings(session, findings)
    except Exception as err:  # noqa: BLE001 - reported in the email and re-raised below
        history_error = f"{type(err).__name__}: {err}"
        print(f"History update failed: {history_error}")

    # If publishing fails, the error makes this run fail, so it is visible as a Lambda error
    send_report(session, findings, summary, history, history_error)

    if history_error:
        raise RuntimeError(f"Finding history update failed: {history_error}")
    return summary