"""Track findings across scans in DynamoDB: new, still open, and resolved."""

import os
from datetime import datetime, timezone

from boto3.dynamodb.conditions import Attr

# Set as an environment variable on the Lambda function
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE")

# Suppressed findings were reviewed and accepted, so they are not tracked
TRACKED_STATUSES = {"FAIL", "ERROR"}


def finding_key(finding):
    """Unique key for one finding, for example SG_OPEN_TO_INTERNET#sg-123 (web)#ap-southeast-2."""
    return f"{finding['check_id']}#{finding['resource']}#{finding['region']}"


def load_open_items(table):
    """Return every finding still marked as open, keyed by finding_key (with pagination)."""
    items = {}
    scan_kwargs = {"FilterExpression": Attr("is_open").eq(True)}
    while True:
        response = table.scan(**scan_kwargs)
        for item in response.get("Items", []):
            items[item["finding_key"]] = item
        if "LastEvaluatedKey" not in response:
            return items
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def track_findings(session, findings):
    """Compare this scan with the stored history.

    Returns {"new": [...], "still_open": [...], "resolved": [...]},
    or None if no table is configured (for example when running locally).
    """
    if not FINDINGS_TABLE:
        print("FINDINGS_TABLE is not set; skipping history")
        return None

    table = session.resource("dynamodb").Table(FINDINGS_TABLE)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    previous = load_open_items(table)
    current = {finding_key(f): f for f in findings if f["status"] in TRACKED_STATUSES}

    new, still_open, resolved = [], [], []

    for key, finding in current.items():
        if key in previous:
            # Seen before and still there: refresh the details and last_seen
            table.update_item(
                Key={"finding_key": key},
                UpdateExpression="SET #status = :status, #severity = :severity, "
                                 "#message = :message, #last_seen = :now",
                ExpressionAttributeNames={
                    "#status": "status",
                    "#severity": "severity",
                    "#message": "message",
                    "#last_seen": "last_seen",
                },
                ExpressionAttributeValues={
                    ":status": finding["status"],
                    ":severity": finding["severity"],
                    ":message": finding["message"],
                    ":now": now,
                },
            )
            still_open.append(finding)
        else:
            # First time (or back after being resolved): store it as a new open finding
            table.put_item(Item={
                "finding_key": key,
                "check_id": finding["check_id"],
                "resource": finding["resource"],
                "region": finding["region"],
                "status": finding["status"],
                "severity": finding["severity"],
                "message": finding["message"],
                "first_seen": now,
                "last_seen": now,
                "is_open": True,
            })
            new.append(finding)

    for key, item in previous.items():
        if key not in current:
            # Open last time, gone now: mark as resolved (the row is kept as history)
            table.update_item(
                Key={"finding_key": key},
                UpdateExpression="SET #is_open = :false, #resolved_at = :now",
                ExpressionAttributeNames={"#is_open": "is_open", "#resolved_at": "resolved_at"},
                ExpressionAttributeValues={":false": False, ":now": now},
            )
            resolved.append(item)

    print(f"History: {len(new)} new, {len(still_open)} still open, {len(resolved)} resolved")
    return {"new": new, "still_open": still_open, "resolved": resolved}