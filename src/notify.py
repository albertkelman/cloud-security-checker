"""Send the scan report by email through Amazon SNS."""

import os
from datetime import datetime, timezone

# Set as an environment variable on the Lambda function
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")

CHECKS_RUN = [
    "S3 public access (account BPA, bucket BPA, bucket policy, bucket ACL)",
    "Root account (MFA, access keys) and IAM users (MFA, access key age)",
    "Security groups open to the internet on sensitive ports (all enabled regions)",
    "CloudTrail (logging, multi-region, log file validation)",
]


def format_finding(finding):
    return (f"- [{finding['severity']}] {finding['check_id']} "
            f"{finding['resource']} ({finding['region']}): {finding['message']}")


def build_subject(summary, history=None):
    """Short subject line. SNS email subjects must be under 100 characters."""
    status = "ACTION NEEDED" if summary["fail"] or summary["error"] else "OK"
    subject = (f"[cloud-security-checker] {status}: "
               f"{summary['fail']} FAIL, {summary['error']} ERROR")
    if history and history["new"]:
        subject += f", {len(history['new'])} NEW"
    return subject


def build_changes_section(history, history_error):
    """What changed since the previous scan."""
    lines = ["Changes since the last scan:"]
    if history_error:
        lines.append(f"- History could not be updated: {history_error}")
        lines.append("- The list below is still complete, but new and resolved items are unknown.")
        return lines
    if history is None:
        lines.append("- History is not configured")
        return lines

    lines.append(f"New ({len(history['new'])}):")
    lines.extend(format_finding(f) for f in history["new"]) if history["new"] else lines.append("- none")
    lines.append(f"Resolved ({len(history['resolved'])}):")
    lines.extend(format_finding(f) for f in history["resolved"]) if history["resolved"] else lines.append("- none")
    lines.append(f"Still open from earlier scans: {len(history['still_open'])}")
    return lines


def build_message(findings, summary, history=None, history_error=None):
    """Plain-text report: changes first, then every finding grouped by status."""
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = [
        ("Problems found (FAIL)", "FAIL"),
        ("Could not check (ERROR) - this is not proof that things are safe", "ERROR"),
        ("Reviewed and accepted (SUPPRESSED)", "SUPPRESSED"),
    ]

    lines = [
        "Cloud Security Checker - scan report",
        f"Scan time: {scan_time}",
        f"Result: {summary['fail']} FAIL, {summary['error']} ERROR, "
        f"{summary['suppressed']} SUPPRESSED",
        "",
    ]
    lines.extend(build_changes_section(history, history_error))
    lines.append("")

    lines.append("All current findings:")
    lines.append("")
    for title, status in sections:
        lines.append(f"{title}:")
        matching = [f for f in findings if f["status"] == status]
        if not matching:
            lines.append("- none")
        for finding in matching:
            lines.append(format_finding(finding))
            if status == "SUPPRESSED":
                lines.append(f"    Reason: {finding['suppression_reason']}")
        lines.append("")

    lines.append("Checks run:")
    lines.extend(f"- {check}" for check in CHECKS_RUN)
    lines.append("")
    lines.append("This report is sent after every scan, even when nothing is wrong.")
    lines.append("If it stops arriving, the scanner itself needs attention.")
    return "\n".join(lines)


def send_report(session, findings, summary, history=None, history_error=None):
    """Publish the report to the SNS topic. Raises an error if publishing fails."""
    if not ALERT_TOPIC_ARN:
        print("ALERT_TOPIC_ARN is not set; skipping email")
        return None

    sns = session.client("sns")
    response = sns.publish(
        TopicArn=ALERT_TOPIC_ARN,
        Subject=build_subject(summary, history),
        Message=build_message(findings, summary, history, history_error),
    )
    print(f"Report published to SNS, message ID {response['MessageId']}")
    return response["MessageId"]