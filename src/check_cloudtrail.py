"""CloudTrail checks. Read-only."""

from botocore.exceptions import BotoCoreError, ClientError

from common import HOME_REGION, error_code, make_finding


def run_cloudtrail_checks(session):
    """Check that a trail is logging, across all regions, with log file validation."""
    cloudtrail = session.client("cloudtrail", region_name=HOME_REGION)
    try:
        # includeShadowTrails=True also returns organization trails
        trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
    except (ClientError, BotoCoreError) as err:
        reason = error_code(err) if isinstance(err, ClientError) else type(err).__name__
        print("  CloudTrail: could not list trails")
        return [make_finding("CLOUDTRAIL_NOT_ENABLED", "account", HOME_REGION, "UNKNOWN", "ERROR",
                             f"Could not list trails: {reason}")]

    logging_trails = []
    status_errors = []
    for trail in trails:
        # The trail status must be read from the trail's home region
        home_region = trail.get("HomeRegion", HOME_REGION)
        try:
            client = session.client("cloudtrail", region_name=home_region)
            status = client.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                logging_trails.append(trail)
        except ClientError as err:
            status_errors.append(f"{trail['Name']} ({error_code(err)})")
        except BotoCoreError as err:
            status_errors.append(f"{trail['Name']} ({type(err).__name__})")

    print(f"  CloudTrail: {len(trails)} trail(s) found, {len(logging_trails)} logging")

    findings = []
    if not logging_trails:
        if status_errors:
            findings.append(make_finding(
                "CLOUDTRAIL_NOT_ENABLED", "account", HOME_REGION, "UNKNOWN", "ERROR",
                f"Could not read trail status: {', '.join(status_errors)}"))
        else:
            findings.append(make_finding(
                "CLOUDTRAIL_NOT_ENABLED", "account", HOME_REGION, "MEDIUM", "FAIL",
                "No CloudTrail trail is logging; only the 90-day event history is available"))
        return findings

    if not any(trail.get("IsMultiRegionTrail") for trail in logging_trails):
        findings.append(make_finding(
            "CLOUDTRAIL_NOT_MULTI_REGION", "account", HOME_REGION, "LOW", "FAIL",
            "Logging trails only cover a single region"))

    # Log file validation proves that log files were not changed or deleted
    for trail in logging_trails:
        if not trail.get("LogFileValidationEnabled"):
            findings.append(make_finding(
                "CLOUDTRAIL_LOG_VALIDATION_OFF", trail["Name"],
                trail.get("HomeRegion", HOME_REGION), "LOW", "FAIL",
                "Log file validation is disabled; log tampering would not be detectable"))

    return findings