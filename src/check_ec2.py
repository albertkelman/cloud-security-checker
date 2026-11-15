"""Security group checks across all enabled regions. Read-only."""

from botocore.exceptions import BotoCoreError, ClientError

from common import HOME_REGION, error_code, make_finding

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    6379: "Redis",
    27017: "MongoDB",
}
DENIED_CODES = {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "AuthFailure"}


def get_enabled_regions(session):
    """Return the names of regions that are enabled for this account."""
    ec2 = session.client("ec2", region_name=HOME_REGION)
    regions = ec2.describe_regions(AllRegions=False)["Regions"]
    return sorted(region["RegionName"] for region in regions)


def open_sources(permission):
    """Return the internet-wide CIDRs (IPv4 or IPv6) in one inbound rule."""
    ipv4 = {r["CidrIp"] for r in permission.get("IpRanges", [])}
    ipv6 = {r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])}
    return (ipv4 | ipv6) & OPEN_CIDRS


def exposed_services(permission):
    """Return the sensitive services that one inbound rule exposes."""
    protocol = permission.get("IpProtocol")
    if protocol == "-1":
        return ["all traffic"]
    if protocol not in ("tcp", "6"):
        return []

    start = permission.get("FromPort")
    end = permission.get("ToPort")
    if start is None or end is None:
        return []

    # A rule can be a port range (for example 0-65535), so check if it covers each port
    return [f"{name} ({port})" for port, name in SENSITIVE_PORTS.items() if start <= port <= end]


def check_region(session, region):
    """Check every security group in one region. Returns (findings, group_count).

    One finding per security group, listing every exposed service, so that each
    finding has a unique history key (check_id + resource + region).
    """
    ec2 = session.client("ec2", region_name=region)
    findings = []
    group_count = 0

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page.get("SecurityGroups", []):
            group_count += 1
            resource = f"{group['GroupId']} ({group.get('GroupName', '')})"

            # Collect every exposed service in this group, across all of its rules
            exposures = {}
            for permission in group.get("IpPermissions", []):
                sources = open_sources(permission)
                if not sources:
                    continue
                for service in exposed_services(permission):
                    exposures.setdefault(service, set()).update(sources)

            if exposures:
                details = "; ".join(
                    f"{service} open to {', '.join(sorted(sources))}"
                    for service, sources in sorted(exposures.items())
                )
                findings.append(make_finding(
                    "SG_OPEN_TO_INTERNET", resource, region, "HIGH", "FAIL",
                    f"Inbound {details}"))

    return findings, group_count


def run_sg_checks(session):
    """Run security group checks in every enabled region and return the findings."""
    try:
        regions = get_enabled_regions(session)
    except (ClientError, BotoCoreError) as err:
        reason = error_code(err) if isinstance(err, ClientError) else type(err).__name__
        return [make_finding("SG_REGIONS", "regions", "global", "UNKNOWN", "ERROR",
                             f"Could not list regions: {reason}")]

    findings = []
    total_groups = 0
    denied_regions = []

    for region in regions:
        try:
            region_findings, group_count = check_region(session, region)
        except ClientError as err:
            if error_code(err) in DENIED_CODES:
                denied_regions.append(region)
            else:
                findings.append(make_finding("SG_OPEN_TO_INTERNET", "security groups", region,
                                             "UNKNOWN", "ERROR", f"Could not check: {error_code(err)}"))
            continue
        except BotoCoreError as err:
            findings.append(make_finding("SG_OPEN_TO_INTERNET", "security groups", region,
                                         "UNKNOWN", "ERROR", f"Could not check: {type(err).__name__}"))
            continue

        findings.extend(region_findings)
        total_groups += group_count

    if denied_regions:
        findings.append(make_finding(
            "SG_REGION_ACCESS", "regions", "multiple", "UNKNOWN", "ERROR",
            f"Could not check {len(denied_regions)} region(s), access denied: "
            f"{', '.join(denied_regions)}"))

    checked = len(regions) - len(denied_regions)
    print(f"  EC2: {total_groups} security group(s) in {checked} of {len(regions)} region(s) checked")
    return findings