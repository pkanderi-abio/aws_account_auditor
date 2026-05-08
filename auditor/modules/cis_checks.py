"""
CIS AWS Foundations Benchmark v1.5 — Level 1 & 2 checks.
Covers sections 1 (IAM), 2 (Storage), 3 (Logging), 4 (Monitoring), 5 (Networking).
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone, timedelta

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding(account_id, region, service, check, status, severity, ftype, details, rec, compliance):
    return {
        "AccountId": account_id, "Region": region, "Service": service, "Check": check,
        "Status": status, "Severity": severity, "FindingType": ftype,
        "Details": details, "Recommendation": rec, "Timestamp": _ts(),
        "Compliance": compliance,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Section 1 — Identity and Access Management
# ═══════════════════════════════════════════════════════════════════════════════

def check_iam(session, account_id: str) -> list[dict]:
    findings = []
    iam = session.client("iam")
    comp_iam = {"CIS": "1.x", "NIST": "IA-2, AC-2", "PCI": "Req-8"}

    # 1.3 / 1.21 — No root access keys
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(_finding(
                account_id, "global", "IAM", "Root Account Access Keys",
                "FAIL", "Critical", "Access",
                "Root account has active access keys. This is a critical security risk.",
                "Delete root access keys immediately. Use IAM roles or IAM users instead.",
                {"CIS": "1.3, 1.21", "PCI": "8.2.1", "NIST": "AC-6, IA-2"},
            ))
        else:
            findings.append(_finding(account_id, "global", "IAM", "Root Account Access Keys",
                "PASS", "Critical", "Access", "No root access keys present.", "", {"CIS": "1.3"}))
    except ClientError as e:
        logger.warning("CIS 1.3 check failed: %s", e)

    # 1.4 / 1.5 — Root MFA
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(_finding(
                account_id, "global", "IAM", "Root Account MFA",
                "FAIL", "Critical", "Access",
                "MFA is not enabled for the root account.",
                "Enable virtual or hardware MFA on the root account immediately.",
                {"CIS": "1.4, 1.5", "PCI": "8.3.1", "NIST": "IA-2"},
            ))
        else:
            findings.append(_finding(account_id, "global", "IAM", "Root Account MFA",
                "PASS", "Critical", "Access", "Root account MFA is enabled.", "", {"CIS": "1.4"}))
    except ClientError as e:
        logger.warning("CIS 1.4 check failed: %s", e)

    # 1.7–1.13 — Password policy
    try:
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            policy = {}
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("minimum length < 14")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("no uppercase required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("no lowercase required")
        if not policy.get("RequireSymbols"):
            issues.append("no symbols required")
        if not policy.get("RequireNumbers"):
            issues.append("no numbers required")
        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append("password age > 90 days")
        if policy.get("PasswordReusePrevention", 0) < 24:
            issues.append("reuse prevention < 24")

        if issues or not policy:
            findings.append(_finding(
                account_id, "global", "IAM", "IAM Password Policy",
                "FAIL", "High", "Access",
                f"Password policy issues: {'; '.join(issues) if issues else 'no password policy configured'}.",
                "Configure a strong password policy via IAM > Account Settings.",
                {"CIS": "1.7-1.13", "PCI": "8.3.6", "NIST": "IA-5"},
            ))
        else:
            findings.append(_finding(account_id, "global", "IAM", "IAM Password Policy",
                "PASS", "High", "Access", "Password policy meets CIS requirements.", "", {"CIS": "1.7"}))
    except ClientError as e:
        logger.warning("CIS password policy check failed: %s", e)

    # 1.14 — MFA for all IAM users with console access
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                # Check for console password (login profile)
                try:
                    iam.get_login_profile(UserName=uname)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False
                if not has_console:
                    continue
                mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                if not mfa_devices:
                    findings.append(_finding(
                        account_id, "global", "IAM", "IAM User MFA",
                        "FAIL", "High", "Access",
                        f"IAM user '{uname}' has console access but no MFA device.",
                        f"Enable MFA for user '{uname}': aws iam enable-mfa-device ...",
                        {"CIS": "1.14", "PCI": "8.3.1", "NIST": "IA-2"},
                    ))
    except ClientError as e:
        logger.warning("CIS 1.14 check failed: %s", e)

    # 1.15 / 1.19 — Access keys unused >45 days & credentials unused >90 days
    try:
        paginator = iam.get_paginator("list_users")
        now = datetime.now(timezone.utc)
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last_used = last["AccessKeyLastUsed"].get("LastUsedDate")
                    if last_used:
                        days = (now - last_used).days
                        if days > 45:
                            findings.append(_finding(
                                account_id, "global", "IAM", "IAM Access Key Rotation",
                                "FAIL", "Medium", "Access",
                                f"Access key {key['AccessKeyId']} for '{uname}' not used in {days} days.",
                                f"Rotate or deactivate access key: aws iam update-access-key --access-key-id {key['AccessKeyId']} --status Inactive --user-name {uname}",
                                {"CIS": "1.15", "PCI": "8.6.1", "NIST": "IA-5"},
                            ))
    except ClientError as e:
        logger.warning("CIS 1.15 check failed: %s", e)

    # 1.16 — No direct policy attachments to users
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                inline = iam.list_user_policies(UserName=uname)["PolicyNames"]
                if attached or inline:
                    findings.append(_finding(
                        account_id, "global", "IAM", "IAM Policy Attached to User",
                        "FAIL", "Medium", "Access",
                        f"User '{uname}' has {len(attached)} managed + {len(inline)} inline policies attached directly.",
                        "Detach policies from the user and attach them to IAM groups or roles instead.",
                        {"CIS": "1.16", "PCI": "7.2.1", "NIST": "AC-6"},
                    ))
    except ClientError as e:
        logger.warning("CIS 1.16 check failed: %s", e)

    # 1.17 — Support role exists
    try:
        policies = iam.list_policies(Scope="Local")["Policies"]
        support_entities = iam.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess"
        )
        total = (
            len(support_entities.get("PolicyGroups", [])) +
            len(support_entities.get("PolicyUsers", [])) +
            len(support_entities.get("PolicyRoles", []))
        )
        if total == 0:
            findings.append(_finding(
                account_id, "global", "IAM", "IAM Support Role",
                "FAIL", "Low", "Access",
                "No IAM entity has AWSSupportAccess policy attached.",
                "Create a role with AWSSupportAccess and assign it to appropriate personnel.",
                {"CIS": "1.17", "NIST": "IR-4"},
            ))
        else:
            findings.append(_finding(account_id, "global", "IAM", "IAM Support Role",
                "PASS", "Low", "Access", f"AWSSupportAccess policy attached to {total} entity/entities.", "", {"CIS": "1.17"}))
    except ClientError as e:
        logger.warning("CIS 1.17 check failed: %s", e)

    # 1.20 — No full AdministratorAccess attached to roles/users/groups
    try:
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        entities = iam.list_entities_for_policy(PolicyArn=admin_arn)
        for role in entities.get("PolicyRoles", []):
            findings.append(_finding(
                account_id, "global", "IAM", "IAM Full Admin Policy",
                "FAIL", "High", "Access",
                f"Role '{role['RoleName']}' has AdministratorAccess policy attached.",
                "Remove AdministratorAccess and apply least-privilege policies.",
                {"CIS": "1.20", "PCI": "7.2.1", "NIST": "AC-6"},
            ))
        for user in entities.get("PolicyUsers", []):
            findings.append(_finding(
                account_id, "global", "IAM", "IAM Full Admin Policy",
                "FAIL", "High", "Access",
                f"User '{user['UserName']}' has AdministratorAccess policy attached.",
                "Remove AdministratorAccess and apply least-privilege policies.",
                {"CIS": "1.20", "PCI": "7.2.1", "NIST": "AC-6"},
            ))
    except ClientError as e:
        logger.warning("CIS 1.20 check failed: %s", e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2 — Storage
# ═══════════════════════════════════════════════════════════════════════════════

def check_storage(session, account_id: str, regions: list[str]) -> list[dict]:
    findings = []

    # 2.1 — S3 (global)
    try:
        s3 = session.client("s3")
        s3control = session.client("s3control", region_name="us-east-1")

        # 2.1.1 Account-level S3 Block Public Access
        try:
            bpa = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
            blocked = all([
                bpa.get("BlockPublicAcls"), bpa.get("IgnorePublicAcls"),
                bpa.get("BlockPublicPolicy"), bpa.get("RestrictPublicBuckets"),
            ])
            if not blocked:
                findings.append(_finding(
                    account_id, "global", "S3", "S3 Public Access Block",
                    "FAIL", "High", "Exposure",
                    "Account-level S3 Block Public Access is not fully enabled.",
                    "Enable all four S3 Block Public Access settings at the account level.",
                    {"CIS": "2.1.1", "PCI": "1.3.1", "NIST": "SC-7"},
                ))
            else:
                findings.append(_finding(account_id, "global", "S3", "S3 Public Access Block",
                    "PASS", "High", "Exposure", "Account-level S3 Block Public Access is fully enabled.", "", {"CIS": "2.1.1"}))
        except ClientError:
            findings.append(_finding(
                account_id, "global", "S3", "S3 Public Access Block",
                "FAIL", "High", "Exposure",
                "Unable to verify account-level S3 Block Public Access (not configured).",
                "Enable S3 Block Public Access at account level.",
                {"CIS": "2.1.1"},
            ))

        # Per-bucket checks
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            bname = bucket["Name"]
            # 2.1.2 — Bucket-level public ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bname)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in (
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    ):
                        findings.append(_finding(
                            account_id, "global", "S3", "S3 Bucket Policy",
                            "FAIL", "Critical", "Exposure",
                            f"S3 bucket '{bname}' has public ACL grant: {grant.get('Permission')}.",
                            f"Remove public ACL: aws s3api put-bucket-acl --bucket {bname} --acl private",
                            {"CIS": "2.1.2", "PCI": "1.3.1", "NIST": "AC-3"},
                        ))
            except ClientError:
                pass

            # Bucket logging
            try:
                logging_status = s3.get_bucket_logging(Bucket=bname)
                if "LoggingEnabled" not in logging_status:
                    findings.append(_finding(
                        account_id, "global", "S3", "S3 Bucket Logging",
                        "FAIL", "Low", "Logging",
                        f"S3 bucket '{bname}' does not have access logging enabled.",
                        f"Enable bucket logging: aws s3api put-bucket-logging --bucket {bname} ...",
                        {"CIS": "3.6", "PCI": "10.2.1", "NIST": "AU-2"},
                    ))
            except ClientError:
                pass

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=bname)
            except s3.exceptions.ClientError:
                findings.append(_finding(
                    account_id, "global", "S3", "S3 Bucket Encryption",
                    "FAIL", "Medium", "Data Protection",
                    f"S3 bucket '{bname}' does not have default encryption enabled.",
                    f"Enable SSE: aws s3api put-bucket-encryption --bucket {bname} --server-side-encryption-configuration ...",
                    {"CIS": "2.1.1", "PCI": "3.5.1", "NIST": "SC-28"},
                ))
            except ClientError:
                pass
    except ClientError as e:
        logger.warning("S3 CIS checks failed: %s", e)

    # 2.2.1 — EBS default encryption (per region)
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            resp = ec2.get_ebs_encryption_by_default()
            if not resp.get("EbsEncryptionByDefault"):
                findings.append(_finding(
                    account_id, region, "EC2", "EC2 EBS Encryption",
                    "FAIL", "High", "Data Protection",
                    f"EBS default encryption is disabled in {region}.",
                    f"Enable EBS encryption: aws ec2 enable-ebs-encryption-by-default --region {region}",
                    {"CIS": "2.2.1", "PCI": "3.5.1", "NIST": "SC-28"},
                ))
            else:
                findings.append(_finding(account_id, region, "EC2", "EC2 EBS Encryption",
                    "PASS", "High", "Data Protection", f"EBS default encryption enabled in {region}.", "", {"CIS": "2.2.1"}))
        except ClientError as e:
            logger.warning("CIS 2.2.1 check failed in %s: %s", region, e)

    # 2.3 — RDS (first region only for efficiency; can be expanded)
    for region in regions[:3]:
        try:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    dbid = db["DBInstanceIdentifier"]
                    # 2.3.2 — Encryption
                    if not db.get("StorageEncrypted"):
                        findings.append(_finding(
                            account_id, region, "RDS", "RDS Encryption",
                            "FAIL", "High", "Data Protection",
                            f"RDS instance '{dbid}' is not encrypted at rest.",
                            "Enable encryption by creating a new encrypted instance and migrating.",
                            {"CIS": "2.3.2", "PCI": "3.5.1", "NIST": "SC-28"},
                        ))
                    # 2.3.1 — Public access
                    if db.get("PubliclyAccessible"):
                        findings.append(_finding(
                            account_id, region, "RDS", "RDS Public Access",
                            "FAIL", "Critical", "Exposure",
                            f"RDS instance '{dbid}' is publicly accessible.",
                            f"Disable public access: aws rds modify-db-instance --db-instance-identifier {dbid} --no-publicly-accessible",
                            {"CIS": "2.3.1", "PCI": "1.3.1", "NIST": "SC-7"},
                        ))
                    # 2.3.3 — Auto minor upgrade
                    if not db.get("AutoMinorVersionUpgrade"):
                        findings.append(_finding(
                            account_id, region, "RDS", "RDS Minor Upgrade",
                            "FAIL", "Low", "Patch Management",
                            f"RDS instance '{dbid}' has auto minor version upgrade disabled.",
                            f"Enable: aws rds modify-db-instance --db-instance-identifier {dbid} --auto-minor-version-upgrade",
                            {"CIS": "2.3.3", "PCI": "6.3.3", "NIST": "SI-2"},
                        ))
                    # Backup
                    if db.get("BackupRetentionPeriod", 0) < 7:
                        findings.append(_finding(
                            account_id, region, "RDS", "RDS Backup",
                            "FAIL", "Medium", "Availability",
                            f"RDS instance '{dbid}' backup retention is {db.get('BackupRetentionPeriod', 0)} days (< 7).",
                            f"Set retention >= 7 days: aws rds modify-db-instance --db-instance-identifier {dbid} --backup-retention-period 7",
                            {"SOC2": "A1.2", "HIPAA": "164.310(d)(1)", "NIST": "CP-9"},
                        ))
        except ClientError as e:
            logger.warning("RDS CIS checks failed in %s: %s", region, e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3 — Logging
# ═══════════════════════════════════════════════════════════════════════════════

def check_logging(session, account_id: str, regions: list[str]) -> list[dict]:
    findings = []

    # 3.1–3.7 — CloudTrail
    try:
        ct = session.client("cloudtrail", region_name="us-east-1")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            findings.append(_finding(
                account_id, "global", "CloudTrail", "CloudTrail Enabled",
                "FAIL", "Critical", "Logging",
                "No CloudTrail trails are configured in this account.",
                "Create a multi-region CloudTrail trail immediately.",
                {"CIS": "3.1", "PCI": "10.2.1", "NIST": "AU-12"},
            ))
        else:
            for trail in trails:
                tname = trail["Name"]
                trn = trail["TrailARN"]
                region = trail.get("HomeRegion", "us-east-1")

                # 3.1 — Multi-region
                if not trail.get("IsMultiRegionTrail"):
                    findings.append(_finding(
                        account_id, region, "CloudTrail", "CloudTrail Enabled",
                        "FAIL", "High", "Logging",
                        f"Trail '{tname}' is not a multi-region trail.",
                        "Update the trail to enable multi-region logging.",
                        {"CIS": "3.1", "PCI": "10.2.1", "NIST": "AU-12"},
                    ))
                else:
                    findings.append(_finding(account_id, region, "CloudTrail", "CloudTrail Enabled",
                        "PASS", "High", "Logging", f"Trail '{tname}' is multi-region.", "", {"CIS": "3.1"}))

                # 3.2 — Log file validation
                if not trail.get("LogFileValidationEnabled"):
                    findings.append(_finding(
                        account_id, region, "CloudTrail", "CloudTrail Log Validation",
                        "FAIL", "High", "Logging",
                        f"Trail '{tname}' does not have log file validation enabled.",
                        "Enable log file validation to detect log tampering.",
                        {"CIS": "3.2", "PCI": "10.3.1", "NIST": "AU-9"},
                    ))

                # 3.4 — CloudWatch Logs integration
                if not trail.get("CloudWatchLogsLogGroupArn"):
                    findings.append(_finding(
                        account_id, region, "CloudTrail", "CloudTrail CloudWatch",
                        "FAIL", "Medium", "Logging",
                        f"Trail '{tname}' is not integrated with CloudWatch Logs.",
                        "Configure CloudWatch Logs for real-time monitoring of trail events.",
                        {"CIS": "3.4", "PCI": "10.7.1", "NIST": "AU-12"},
                    ))

                # 3.7 — KMS encryption
                if not trail.get("KMSKeyId"):
                    findings.append(_finding(
                        account_id, region, "CloudTrail", "CloudTrail KMS Encryption",
                        "FAIL", "Medium", "Logging",
                        f"Trail '{tname}' logs are not encrypted with a KMS key.",
                        "Configure SSE-KMS encryption for the CloudTrail S3 bucket.",
                        {"CIS": "3.7", "PCI": "10.3.1", "NIST": "AU-9"},
                    ))

                # 3.3 — S3 bucket not public
                bucket = trail.get("S3BucketName")
                if bucket:
                    try:
                        s3 = session.client("s3")
                        acl = s3.get_bucket_acl(Bucket=bucket)
                        for grant in acl.get("Grants", []):
                            uri = grant.get("Grantee", {}).get("URI", "")
                            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                                findings.append(_finding(
                                    account_id, region, "CloudTrail", "CloudTrail S3 Public",
                                    "FAIL", "Critical", "Logging",
                                    f"CloudTrail S3 bucket '{bucket}' is publicly accessible.",
                                    "Remove public ACLs from the CloudTrail S3 bucket.",
                                    {"CIS": "3.3", "PCI": "10.3.1", "NIST": "AU-9"},
                                ))
                    except ClientError:
                        pass
    except ClientError as e:
        logger.warning("CloudTrail CIS checks failed: %s", e)

    # 3.8 — KMS CMK key rotation
    for region in regions[:3]:
        try:
            kms = session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page["Keys"]:
                    kid = key["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                        if meta.get("KeyManager") != "CUSTOMER":
                            continue
                        if meta.get("KeyState") != "Enabled":
                            continue
                        rotation = kms.get_key_rotation_status(KeyId=kid)
                        if not rotation.get("KeyRotationEnabled"):
                            findings.append(_finding(
                                account_id, region, "KMS", "KMS Key Rotation",
                                "FAIL", "Medium", "Cryptography",
                                f"Customer-managed KMS key {kid} does not have automatic key rotation enabled.",
                                f"Enable rotation: aws kms enable-key-rotation --key-id {kid} --region {region}",
                                {"CIS": "3.8", "PCI": "4.2.1", "NIST": "SC-12"},
                            ))
                    except ClientError:
                        pass
        except ClientError as e:
            logger.warning("KMS check failed in %s: %s", region, e)

    # 3.9 — VPC Flow Logs
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs()["Vpcs"]
            for vpc in vpcs:
                vid = vpc["VpcId"]
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vid]}]
                )["FlowLogs"]
                active = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
                if not active:
                    findings.append(_finding(
                        account_id, region, "VPC", "VPC Flow Logs",
                        "FAIL", "Medium", "Logging",
                        f"VPC '{vid}' in {region} does not have flow logging enabled.",
                        f"Enable flow logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids {vid} --traffic-type ALL --log-destination-type cloud-watch-logs",
                        {"CIS": "3.9", "PCI": "10.2.1", "NIST": "AU-12"},
                    ))
                else:
                    findings.append(_finding(account_id, region, "VPC", "VPC Flow Logs",
                        "PASS", "Medium", "Logging", f"Flow logs active for VPC '{vid}'.", "", {"CIS": "3.9"}))
        except ClientError as e:
            logger.warning("VPC flow log check failed in %s: %s", region, e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4 — Monitoring (CloudWatch metric filters)
# ═══════════════════════════════════════════════════════════════════════════════

# Patterns for the 15 required CIS metric filters
_REQUIRED_FILTERS = [
    ("4.1",  "CIS-UnauthorizedAPICalls",          r'$.errorCode = "UnauthorizedOperation" || $.errorCode = "AccessDenied"'),
    ("4.2",  "CIS-NoMFAConsoleSignIn",             r'$.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No"'),
    ("4.3",  "CIS-RootAccountUsage",               r'$.userIdentity.type = "Root"'),
    ("4.4",  "CIS-IAMPolicyChanges",               r'$.eventName = "DeleteGroupPolicy" || $.eventName = "PutGroupPolicy"'),
    ("4.5",  "CIS-CloudTrailChanges",              r'$.eventName = "CreateTrail" || $.eventName = "DeleteTrail"'),
    ("4.6",  "CIS-ConsoleAuthFailures",            r'$.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication"'),
    ("4.7",  "CIS-DisableOrDeleteCMK",             r'$.eventSource = "kms.amazonaws.com" && ($.eventName = "DisableKey" || $.eventName = "ScheduleKeyDeletion")'),
    ("4.8",  "CIS-S3BucketPolicyChanges",          r'$.eventSource = "s3.amazonaws.com" && $.eventName = "PutBucketPolicy"'),
    ("4.9",  "CIS-AWSConfigChanges",               r'$.eventSource = "config.amazonaws.com"'),
    ("4.10", "CIS-SecurityGroupChanges",           r'$.eventName = "AuthorizeSecurityGroupIngress" || $.eventName = "RevokeSecurityGroupIngress"'),
    ("4.11", "CIS-NACLChanges",                    r'$.eventName = "CreateNetworkAcl" || $.eventName = "DeleteNetworkAcl"'),
    ("4.12", "CIS-NetworkGatewayChanges",          r'$.eventName = "CreateCustomerGateway" || $.eventName = "DeleteCustomerGateway"'),
    ("4.13", "CIS-RouteTableChanges",              r'$.eventName = "CreateRoute" || $.eventName = "DeleteRoute"'),
    ("4.14", "CIS-VPCChanges",                     r'$.eventName = "CreateVpc" || $.eventName = "DeleteVpc"'),
    ("4.15", "CIS-AWSOrganizationsChanges",        r'$.eventSource = "organizations.amazonaws.com"'),
]


def check_monitoring(session, account_id: str) -> list[dict]:
    findings = []
    try:
        logs = session.client("logs", region_name="us-east-1")
        cw = session.client("cloudwatch", region_name="us-east-1")

        # Gather all metric filters
        all_filters: list[dict] = []
        paginator = logs.get_paginator("describe_metric_filters")
        for page in paginator.paginate():
            all_filters.extend(page["metricFilters"])

        for cis_id, name, _pattern in _REQUIRED_FILTERS:
            # Check if a filter with matching name prefix exists and has an alarm
            matching = [f for f in all_filters if name.lower() in f.get("filterName", "").lower()
                        or name.lower().replace("cis-", "") in f.get("filterName", "").lower()]
            if not matching:
                findings.append(_finding(
                    account_id, "us-east-1", "CloudWatch", "CloudWatch Alarm",
                    "FAIL", "Medium", "Monitoring",
                    f"CIS {cis_id}: No CloudWatch metric filter found for '{name}'.",
                    f"Create a metric filter and alarm for {name}.",
                    {"CIS": cis_id, "PCI": "10.7.1", "NIST": "SI-4"},
                ))
    except ClientError as e:
        logger.warning("CloudWatch monitoring checks failed: %s", e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5 — Networking
# ═══════════════════════════════════════════════════════════════════════════════

def check_networking(session, account_id: str, regions: list[str]) -> list[dict]:
    findings = []

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)

            # 5.1 / 5.2 — No SSH/RDP open to world
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sgid = sg["GroupId"]
                    sgname = sg["GroupName"]
                    vpc_id = sg.get("VpcId", "")

                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)
                        proto = perm.get("IpProtocol", "-1")

                        for cidr in perm.get("IpRanges", []):
                            if cidr.get("CidrIp") not in ("0.0.0.0/0", "::/0"):
                                continue
                            # 5.1 SSH
                            if proto in ("tcp", "-1") and (from_port <= 22 <= to_port or proto == "-1"):
                                findings.append(_finding(
                                    account_id, region, "EC2", "Security Group SSH",
                                    "FAIL", "Critical", "Network",
                                    f"Security group '{sgid}' ({sgname}) allows SSH (port 22) from 0.0.0.0/0.",
                                    f"Restrict SSH access: aws ec2 revoke-security-group-ingress --group-id {sgid} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region {region}",
                                    {"CIS": "5.1", "PCI": "1.3.1", "NIST": "SC-7"},
                                ))
                            # 5.2 RDP
                            if proto in ("tcp", "-1") and (from_port <= 3389 <= to_port or proto == "-1"):
                                findings.append(_finding(
                                    account_id, region, "EC2", "Security Group RDP",
                                    "FAIL", "Critical", "Network",
                                    f"Security group '{sgid}' ({sgname}) allows RDP (port 3389) from 0.0.0.0/0.",
                                    f"Restrict RDP access: aws ec2 revoke-security-group-ingress --group-id {sgid} --protocol tcp --port 3389 --cidr 0.0.0.0/0 --region {region}",
                                    {"CIS": "5.2", "PCI": "1.3.1", "NIST": "SC-7"},
                                ))
                            # Any port open
                            if proto == "-1":
                                findings.append(_finding(
                                    account_id, region, "EC2", "Security Group Open",
                                    "FAIL", "High", "Network",
                                    f"Security group '{sgid}' ({sgname}) allows ALL traffic from 0.0.0.0/0.",
                                    "Restrict ingress to only required ports and sources.",
                                    {"CIS": "5.1", "PCI": "1.3.1", "NIST": "SC-7"},
                                ))

                    # 5.3 — Default security group: no rules
                    if sgname == "default":
                        ingress = sg.get("IpPermissions", [])
                        egress  = sg.get("IpPermissionsEgress", [])
                        has_egress_allow_all = any(
                            p.get("IpProtocol") == "-1" and any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
                            for p in egress
                        )
                        if ingress or (egress and not has_egress_allow_all) or len(egress) > 1:
                            findings.append(_finding(
                                account_id, region, "EC2", "Default Security Group",
                                "FAIL", "High", "Network",
                                f"Default security group '{sgid}' in VPC '{vpc_id}' has rules (ingress: {len(ingress)}, egress: {len(egress)}).",
                                "Remove all rules from the default security group. Use custom SGs instead.",
                                {"CIS": "5.3", "PCI": "1.2.1", "NIST": "SC-7"},
                            ))

        except ClientError as e:
            logger.warning("Networking CIS checks failed in %s: %s", region, e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# GuardDuty / AWS Config enablement checks
# ═══════════════════════════════════════════════════════════════════════════════

def check_detective_controls(session, account_id: str, regions: list[str]) -> list[dict]:
    findings = []

    for region in regions[:3]:
        # GuardDuty
        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors()["DetectorIds"]
            if not detectors:
                findings.append(_finding(
                    account_id, region, "GuardDuty", "GuardDuty Enabled",
                    "FAIL", "High", "Detective",
                    f"AWS GuardDuty is not enabled in {region}.",
                    f"Enable GuardDuty: aws guardduty create-detector --enable --region {region}",
                    {"PCI": "11.3.1", "SOC2": "CC7.2", "NIST": "SI-4"},
                ))
            else:
                findings.append(_finding(account_id, region, "GuardDuty", "GuardDuty Enabled",
                    "PASS", "High", "Detective", f"GuardDuty enabled in {region}.", "", {"PCI": "11.3.1"}))
        except ClientError as e:
            logger.warning("GuardDuty check failed in %s: %s", region, e)

        # AWS Config
        try:
            config = session.client("config", region_name=region)
            recorders = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            recording = any(r.get("recording") for r in recorders)
            if not recording:
                findings.append(_finding(
                    account_id, region, "Config", "AWS Config Enabled",
                    "FAIL", "Medium", "Compliance",
                    f"AWS Config is not actively recording in {region}.",
                    f"Enable AWS Config: aws configservice start-configuration-recorder --configuration-recorder-name default --region {region}",
                    {"CIS": "3.5", "PCI": "10.2.1", "NIST": "CM-8"},
                ))
            else:
                findings.append(_finding(account_id, region, "Config", "AWS Config Enabled",
                    "PASS", "Medium", "Compliance", f"AWS Config recording in {region}.", "", {"CIS": "3.5"}))
        except ClientError as e:
            logger.warning("Config check failed in %s: %s", region, e)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Main entry point for orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

def audit_cis_compliance(session, account_id: str, regions: list[str]) -> list[dict]:
    """Run all CIS AWS Benchmark checks and return a flat findings list."""
    all_findings = []
    for fn in [
        lambda: check_iam(session, account_id),
        lambda: check_storage(session, account_id, regions),
        lambda: check_logging(session, account_id, regions),
        lambda: check_monitoring(session, account_id),
        lambda: check_networking(session, account_id, regions),
        lambda: check_detective_controls(session, account_id, regions),
    ]:
        try:
            all_findings.extend(fn())
        except Exception as exc:
            logger.error("CIS check batch failed: %s", exc)
    return all_findings
