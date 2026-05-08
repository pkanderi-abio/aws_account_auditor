"""
Maps audit check names to compliance framework control IDs and descriptions.
Supports CIS AWS Benchmarks v1.5, PCI-DSS v4.0, SOC 2 TSC, HIPAA, NIST 800-53 Rev5.
"""

from __future__ import annotations

# ── CIS AWS Foundations Benchmark v1.5 controls ───────────────────────────────
CIS_CONTROLS: dict[str, dict] = {
    "1.1":  {"title": "Maintain current contact details",           "section": "Identity and Access Management"},
    "1.2":  {"title": "Ensure security contact info is registered",  "section": "Identity and Access Management"},
    "1.3":  {"title": "Ensure no root user access keys exist",       "section": "Identity and Access Management"},
    "1.4":  {"title": "Ensure MFA is enabled for the root account",  "section": "Identity and Access Management"},
    "1.5":  {"title": "Ensure hardware MFA for root account",        "section": "Identity and Access Management"},
    "1.6":  {"title": "Eliminate use of root account",               "section": "Identity and Access Management"},
    "1.7":  {"title": "Password policy min length ≥ 14",             "section": "Identity and Access Management"},
    "1.8":  {"title": "Password policy require uppercase",           "section": "Identity and Access Management"},
    "1.9":  {"title": "Password policy require lowercase",           "section": "Identity and Access Management"},
    "1.10": {"title": "Password policy require symbols",             "section": "Identity and Access Management"},
    "1.11": {"title": "Password policy require numbers",             "section": "Identity and Access Management"},
    "1.12": {"title": "Password expiry ≤ 90 days",                  "section": "Identity and Access Management"},
    "1.13": {"title": "Password reuse prevention ≥ 24",             "section": "Identity and Access Management"},
    "1.14": {"title": "MFA for all console users",                   "section": "Identity and Access Management"},
    "1.15": {"title": "No active access keys unused >45 days",      "section": "Identity and Access Management"},
    "1.16": {"title": "Ensure IAM policies attached only to groups/roles", "section": "Identity and Access Management"},
    "1.17": {"title": "Ensure a support role for AWS Support",       "section": "Identity and Access Management"},
    "1.18": {"title": "Ensure instance profiles are used for EC2",   "section": "Identity and Access Management"},
    "1.19": {"title": "Expire credentials unused > 90 days",         "section": "Identity and Access Management"},
    "1.20": {"title": "No full AdministratorAccess managed policy attached", "section": "Identity and Access Management"},
    "1.21": {"title": "Avoid creating IAM access keys for root",     "section": "Identity and Access Management"},
    "2.1.1": {"title": "S3 block public access (account level)",     "section": "Storage"},
    "2.1.2": {"title": "S3 bucket no public read ACL",               "section": "Storage"},
    "2.1.3": {"title": "S3 bucket no public write ACL",              "section": "Storage"},
    "2.2.1": {"title": "EBS default encryption enabled",             "section": "Storage"},
    "2.3.1": {"title": "RDS snapshot not public",                    "section": "Storage"},
    "2.3.2": {"title": "RDS encryption at rest",                     "section": "Storage"},
    "2.3.3": {"title": "RDS auto minor upgrade enabled",             "section": "Storage"},
    "2.4.1": {"title": "ECR image scan on push",                     "section": "Storage"},
    "3.1":  {"title": "CloudTrail enabled in all regions",           "section": "Logging"},
    "3.2":  {"title": "CloudTrail log file validation enabled",      "section": "Logging"},
    "3.3":  {"title": "CloudTrail S3 bucket not publicly accessible","section": "Logging"},
    "3.4":  {"title": "CloudTrail integrated with CloudWatch Logs",  "section": "Logging"},
    "3.5":  {"title": "AWS Config enabled",                          "section": "Logging"},
    "3.6":  {"title": "S3 bucket access logging on CloudTrail bucket","section": "Logging"},
    "3.7":  {"title": "CloudTrail logs encrypted at rest (SSE-KMS)", "section": "Logging"},
    "3.8":  {"title": "Customer-managed KMS key rotation enabled",   "section": "Logging"},
    "3.9":  {"title": "VPC flow logging enabled",                    "section": "Logging"},
    "3.10": {"title": "Object-level logging on CloudTrail S3 bucket","section": "Logging"},
    "3.11": {"title": "Object-level write logging for all S3",       "section": "Logging"},
    "4.1":  {"title": "Metric filter: unauthorised API calls",       "section": "Monitoring"},
    "4.2":  {"title": "Metric filter: console sign-in without MFA",  "section": "Monitoring"},
    "4.3":  {"title": "Metric filter: root account usage",           "section": "Monitoring"},
    "4.4":  {"title": "Metric filter: IAM policy changes",           "section": "Monitoring"},
    "4.5":  {"title": "Metric filter: CloudTrail configuration changes", "section": "Monitoring"},
    "4.6":  {"title": "Metric filter: console auth failures",        "section": "Monitoring"},
    "4.7":  {"title": "Metric filter: CMK deletion/disabling",       "section": "Monitoring"},
    "4.8":  {"title": "Metric filter: S3 bucket policy changes",     "section": "Monitoring"},
    "4.9":  {"title": "Metric filter: AWS Config changes",           "section": "Monitoring"},
    "4.10": {"title": "Metric filter: security group changes",       "section": "Monitoring"},
    "4.11": {"title": "Metric filter: NACL changes",                 "section": "Monitoring"},
    "4.12": {"title": "Metric filter: network gateway changes",      "section": "Monitoring"},
    "4.13": {"title": "Metric filter: route table changes",          "section": "Monitoring"},
    "4.14": {"title": "Metric filter: VPC changes",                  "section": "Monitoring"},
    "4.15": {"title": "Metric filter: AWS Organizations changes",    "section": "Monitoring"},
    "5.1":  {"title": "No security group allows 0.0.0.0/0 SSH (22)", "section": "Networking"},
    "5.2":  {"title": "No security group allows 0.0.0.0/0 RDP (3389)","section": "Networking"},
    "5.3":  {"title": "Default security group restricts all traffic","section": "Networking"},
    "5.4":  {"title": "VPC peering routing tables least-privilege",  "section": "Networking"},
    "5.5":  {"title": "No network access control lists allow 0.0.0.0/0 ingress", "section": "Networking"},
    "5.6":  {"title": "EC2 instances should not have public IPs in VPC", "section": "Networking"},
}

# ── PCI-DSS v4.0 requirements ─────────────────────────────────────────────────
PCI_CONTROLS: dict[str, dict] = {
    "1.2.1": {"title": "Network controls between trusted and untrusted networks", "section": "Network Security Controls"},
    "1.3.1": {"title": "Restrict inbound traffic to that which is necessary",    "section": "Network Security Controls"},
    "1.3.2": {"title": "Restrict outbound traffic from the cardholder data environment", "section": "Network Security Controls"},
    "2.2.1": {"title": "Configuration standards cover all system components",    "section": "Secure Configurations"},
    "2.2.7": {"title": "All non-console admin access encrypted with strong cryptography", "section": "Secure Configurations"},
    "3.3.1": {"title": "SAD not retained after authorization",                   "section": "Protect Stored Data"},
    "3.5.1": {"title": "PAN rendered unreadable (hashing/truncation/tokens/encryption)", "section": "Protect Stored Data"},
    "4.2.1": {"title": "Strong cryptography for PAN in transit",                "section": "Protect Data in Transit"},
    "6.3.3": {"title": "Security patches applied within defined timeframes",    "section": "Secure Development"},
    "7.2.1": {"title": "Access control systems limit access to least privilege","section": "Restrict Access by Need to Know"},
    "7.3.1": {"title": "All user IDs and authentication credentials managed",   "section": "Restrict Access by Need to Know"},
    "8.2.1": {"title": "All users assigned a unique ID",                        "section": "Identify and Authenticate"},
    "8.3.1": {"title": "MFA for all non-console access into the CDE",           "section": "Identify and Authenticate"},
    "8.3.6": {"title": "Passwords/passphrases minimum complexity",              "section": "Identify and Authenticate"},
    "8.6.1": {"title": "System/application accounts managed via policies",      "section": "Identify and Authenticate"},
    "10.2.1": {"title": "Audit logs capture all individual user access",        "section": "Log and Monitor"},
    "10.3.1": {"title": "Audit log files protected from destruction/modification", "section": "Log and Monitor"},
    "10.5.1": {"title": "Retain audit log history for at least 12 months",      "section": "Log and Monitor"},
    "10.7.1": {"title": "Failures of critical security controls detected",      "section": "Log and Monitor"},
    "11.3.1": {"title": "Internal vulnerability scans performed quarterly",     "section": "Test Security"},
    "11.4.1": {"title": "Penetration testing methodology defined",              "section": "Test Security"},
    "12.3.1": {"title": "Each PCI DSS requirement managed by policies",         "section": "Org Security Policy"},
    "12.10.1": {"title": "Incident response plan created and ready to activate","section": "Org Security Policy"},
}

# ── SOC 2 Trust Services Criteria (2017) ─────────────────────────────────────
SOC2_CONTROLS: dict[str, dict] = {
    "CC1.1": {"title": "COSO Principle 1: demonstrates commitment to integrity", "section": "Control Environment"},
    "CC2.2": {"title": "Internal communication of information for internal control", "section": "Communication"},
    "CC3.2": {"title": "Identifies risk to achievement of objectives",           "section": "Risk Assessment"},
    "CC5.2": {"title": "Deploys control activities to mitigate risks",           "section": "Control Activities"},
    "CC6.1": {"title": "Logical access security software / policies",            "section": "Logical Access"},
    "CC6.2": {"title": "New internal and external users provisioned with proper access", "section": "Logical Access"},
    "CC6.3": {"title": "Access removed in timely manner when no longer needed",  "section": "Logical Access"},
    "CC6.6": {"title": "Logical access security to prevent unauthorized access from outside", "section": "Logical Access"},
    "CC6.7": {"title": "Restrict transmission of information to authorized users","section": "Logical Access"},
    "CC6.8": {"title": "Controls prevent or detect unauthorized or malicious software", "section": "Logical Access"},
    "CC7.1": {"title": "Detect and monitor for configuration changes",           "section": "System Operations"},
    "CC7.2": {"title": "Monitor system components for anomalies",                "section": "System Operations"},
    "CC7.3": {"title": "Evaluate security events to determine incidents",        "section": "System Operations"},
    "CC7.4": {"title": "Respond to identified security incidents",               "section": "System Operations"},
    "CC8.1": {"title": "Authorise, design, develop and implement infrastructure changes", "section": "Change Management"},
    "CC9.1": {"title": "Identify, assess, and manage risks from vendors",        "section": "Risk Mitigation"},
    "A1.1":  {"title": "Current processing capacity and usage",                  "section": "Availability"},
    "A1.2":  {"title": "Environmental, physical, and logical controls protect availability", "section": "Availability"},
    "C1.1":  {"title": "Identify and maintain confidential information",         "section": "Confidentiality"},
    "C1.2":  {"title": "Dispose of confidential information to meet entity objectives", "section": "Confidentiality"},
    "PI1.1": {"title": "Inputs complete, accurate, timely, and authorised",     "section": "Processing Integrity"},
}

# ── HIPAA Security Rule safeguards ────────────────────────────────────────────
HIPAA_CONTROLS: dict[str, dict] = {
    "164.308(a)(1)": {"title": "Risk analysis — identify threats to ePHI",       "section": "Administrative Safeguards"},
    "164.308(a)(3)": {"title": "Workforce access management",                    "section": "Administrative Safeguards"},
    "164.308(a)(5)": {"title": "Security awareness and training",                "section": "Administrative Safeguards"},
    "164.308(a)(6)": {"title": "Security incident procedures",                   "section": "Administrative Safeguards"},
    "164.310(a)(2)": {"title": "Facility access controls",                       "section": "Physical Safeguards"},
    "164.310(d)(1)": {"title": "Device and media controls",                      "section": "Physical Safeguards"},
    "164.312(a)(1)": {"title": "Access control — unique user identification",    "section": "Technical Safeguards"},
    "164.312(a)(2)": {"title": "Automatic logoff and encryption/decryption",     "section": "Technical Safeguards"},
    "164.312(b)":    {"title": "Audit controls — activity logs",                 "section": "Technical Safeguards"},
    "164.312(c)(1)": {"title": "Integrity — protect ePHI from improper alteration", "section": "Technical Safeguards"},
    "164.312(d)":    {"title": "Person or entity authentication",                "section": "Technical Safeguards"},
    "164.312(e)(1)": {"title": "Transmission security — encryption in transit",  "section": "Technical Safeguards"},
    "164.312(e)(2)": {"title": "Encryption and decryption of ePHI",             "section": "Technical Safeguards"},
}

# ── NIST SP 800-53 Rev 5 control families ────────────────────────────────────
NIST_CONTROLS: dict[str, dict] = {
    "AC-1":  {"title": "Access Control Policy and Procedures",                  "section": "Access Control"},
    "AC-2":  {"title": "Account Management",                                    "section": "Access Control"},
    "AC-3":  {"title": "Access Enforcement",                                    "section": "Access Control"},
    "AC-4":  {"title": "Information Flow Enforcement",                          "section": "Access Control"},
    "AC-6":  {"title": "Least Privilege",                                       "section": "Access Control"},
    "AC-17": {"title": "Remote Access",                                         "section": "Access Control"},
    "AU-2":  {"title": "Event Logging",                                         "section": "Audit and Accountability"},
    "AU-3":  {"title": "Content of Audit Records",                             "section": "Audit and Accountability"},
    "AU-9":  {"title": "Protection of Audit Information",                       "section": "Audit and Accountability"},
    "AU-11": {"title": "Audit Record Retention",                               "section": "Audit and Accountability"},
    "AU-12": {"title": "Audit Record Generation",                              "section": "Audit and Accountability"},
    "CM-2":  {"title": "Baseline Configuration",                               "section": "Configuration Management"},
    "CM-6":  {"title": "Configuration Settings",                               "section": "Configuration Management"},
    "CM-7":  {"title": "Least Functionality",                                  "section": "Configuration Management"},
    "CM-8":  {"title": "System Component Inventory",                           "section": "Configuration Management"},
    "IA-2":  {"title": "Identification and Authentication (Org Users)",         "section": "Identification and Authentication"},
    "IA-3":  {"title": "Device Identification and Authentication",              "section": "Identification and Authentication"},
    "IA-5":  {"title": "Authenticator Management",                             "section": "Identification and Authentication"},
    "IA-8":  {"title": "Identification and Authentication (Non-Org Users)",    "section": "Identification and Authentication"},
    "IR-4":  {"title": "Incident Handling",                                    "section": "Incident Response"},
    "IR-5":  {"title": "Incident Monitoring",                                  "section": "Incident Response"},
    "RA-3":  {"title": "Risk Assessment",                                      "section": "Risk Assessment"},
    "RA-5":  {"title": "Vulnerability Monitoring and Scanning",                "section": "Risk Assessment"},
    "SA-10": {"title": "Developer Configuration Management",                   "section": "System Acquisition"},
    "SC-5":  {"title": "Denial of Service Protection",                         "section": "System and Comms Protection"},
    "SC-7":  {"title": "Boundary Protection",                                  "section": "System and Comms Protection"},
    "SC-8":  {"title": "Transmission Confidentiality and Integrity",           "section": "System and Comms Protection"},
    "SC-12": {"title": "Cryptographic Key Establishment and Management",       "section": "System and Comms Protection"},
    "SC-28": {"title": "Protection of Information at Rest",                    "section": "System and Comms Protection"},
    "SI-2":  {"title": "Flaw Remediation",                                     "section": "System and Information Integrity"},
    "SI-3":  {"title": "Malicious Code Protection",                            "section": "System and Information Integrity"},
    "SI-4":  {"title": "System Monitoring",                                    "section": "System and Information Integrity"},
}

# ── Check-name → multi-framework control mapping ─────────────────────────────
# Keys match the `check_name` field stored in the findings table.
FINDING_CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    # IAM
    "Root Account MFA":            {"CIS": ["1.4", "1.5"], "PCI": ["8.3.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"], "NIST": ["IA-2"]},
    "Root Account Access Keys":    {"CIS": ["1.3", "1.21"], "PCI": ["8.2.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["AC-6", "IA-2"]},
    "Root Account Usage":          {"CIS": ["1.6"], "PCI": ["8.2.1"], "SOC2": ["CC6.2"], "HIPAA": ["164.312(a)(1)"], "NIST": ["AC-2"]},
    "IAM Password Policy":         {"CIS": ["1.7","1.8","1.9","1.10","1.11","1.12","1.13"], "PCI": ["8.3.6"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["IA-5"]},
    "IAM User MFA":                {"CIS": ["1.14"], "PCI": ["8.3.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(d)"], "NIST": ["IA-2"]},
    "IAM User Activity":           {"CIS": ["1.15", "1.19"], "PCI": ["8.6.1"], "SOC2": ["CC6.3"], "HIPAA": ["164.308(a)(3)"], "NIST": ["AC-2"]},
    "IAM Access Key Rotation":     {"CIS": ["1.15"], "PCI": ["8.6.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["IA-5"]},
    "IAM Full Admin Policy":       {"CIS": ["1.20"], "PCI": ["7.2.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.308(a)(3)"], "NIST": ["AC-6"]},
    "IAM Policy Attached to User": {"CIS": ["1.16"], "PCI": ["7.2.1"], "SOC2": ["CC6.2"], "HIPAA": ["164.308(a)(3)"], "NIST": ["AC-6"]},
    "IAM Support Role":            {"CIS": ["1.17"], "SOC2": ["CC7.4"], "NIST": ["IR-4"]},
    "Unused IAM Credentials":      {"CIS": ["1.19"], "PCI": ["8.6.1"], "SOC2": ["CC6.3"], "HIPAA": ["164.308(a)(3)"], "NIST": ["AC-2"]},
    # S3
    "S3 Public Access Block":      {"CIS": ["2.1.1", "2.1.2", "2.1.3"], "PCI": ["1.3.1"], "SOC2": ["CC6.6", "C1.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["AC-3", "SC-7"]},
    "S3 Bucket Logging":           {"CIS": ["3.6"], "PCI": ["10.2.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "NIST": ["AU-2", "AU-12"]},
    "S3 Bucket Encryption":        {"CIS": ["2.1.1"], "PCI": ["3.5.1"], "SOC2": ["C1.1"], "HIPAA": ["164.312(a)(2)"], "NIST": ["SC-28"]},
    "S3 Bucket Policy":            {"CIS": ["2.1.2"], "PCI": ["1.3.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["AC-3"]},
    "S3 Versioning":               {"CIS": ["2.1.1"], "SOC2": ["A1.2"], "HIPAA": ["164.312(c)(1)"], "NIST": ["SI-2"]},
    # CloudTrail
    "CloudTrail Enabled":          {"CIS": ["3.1"], "PCI": ["10.2.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "NIST": ["AU-12"]},
    "CloudTrail Log Validation":   {"CIS": ["3.2"], "PCI": ["10.3.1"], "SOC2": ["CC7.1"], "HIPAA": ["164.312(c)(1)"], "NIST": ["AU-9"]},
    "CloudTrail S3 Public":        {"CIS": ["3.3"], "PCI": ["10.3.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(b)"], "NIST": ["AU-9"]},
    "CloudTrail CloudWatch":       {"CIS": ["3.4"], "PCI": ["10.7.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "NIST": ["AU-12", "SI-4"]},
    "CloudTrail KMS Encryption":   {"CIS": ["3.7"], "PCI": ["10.3.1"], "SOC2": ["CC6.7"], "HIPAA": ["164.312(a)(2)"], "NIST": ["AU-9", "SC-28"]},
    "KMS Key Rotation":            {"CIS": ["3.8"], "PCI": ["4.2.1"], "SOC2": ["CC6.7"], "HIPAA": ["164.312(e)(2)"], "NIST": ["SC-12"]},
    # VPC / Network
    "VPC Flow Logs":               {"CIS": ["3.9"], "PCI": ["10.2.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "NIST": ["AU-12", "SI-4"]},
    "Security Group SSH":          {"CIS": ["5.1"], "PCI": ["1.3.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["SC-7", "AC-17"]},
    "Security Group RDP":          {"CIS": ["5.2"], "PCI": ["1.3.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["SC-7", "AC-17"]},
    "Default Security Group":      {"CIS": ["5.3"], "PCI": ["1.2.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["SC-7", "CM-7"]},
    "Security Group Open":         {"CIS": ["5.1", "5.2"], "PCI": ["1.3.1", "1.3.2"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["SC-7"]},
    "Network Access Control List": {"CIS": ["5.5"], "PCI": ["1.2.1"], "SOC2": ["CC6.6"], "NIST": ["SC-7"]},
    "EC2 Public IP":               {"CIS": ["5.6"], "PCI": ["1.3.1"], "SOC2": ["CC6.6"], "NIST": ["SC-7"]},
    # EC2 / Compute
    "EC2 Instance Metadata":       {"CIS": ["5.6"], "SOC2": ["CC6.8"], "NIST": ["CM-7", "AC-17"]},
    "EC2 EBS Encryption":          {"CIS": ["2.2.1"], "PCI": ["3.5.1"], "SOC2": ["C1.1"], "HIPAA": ["164.312(a)(2)"], "NIST": ["SC-28"]},
    "EC2 Patch Compliance":        {"PCI": ["6.3.3"], "SOC2": ["CC7.1"], "HIPAA": ["164.308(a)(5)"], "NIST": ["SI-2"]},
    "IAM Instance Profile":        {"CIS": ["1.18"], "SOC2": ["CC6.1"], "NIST": ["AC-6"]},
    # RDS / Databases
    "RDS Encryption":              {"CIS": ["2.3.2"], "PCI": ["3.5.1"], "SOC2": ["C1.1"], "HIPAA": ["164.312(a)(2)"], "NIST": ["SC-28"]},
    "RDS Public Access":           {"CIS": ["2.3.1"], "PCI": ["1.3.1"], "SOC2": ["CC6.6"], "HIPAA": ["164.312(a)(1)"], "NIST": ["SC-7"]},
    "RDS Snapshot Public":         {"CIS": ["2.3.1"], "PCI": ["3.5.1"], "SOC2": ["C1.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["AC-3"]},
    "RDS Backup":                  {"SOC2": ["A1.2"], "HIPAA": ["164.310(d)(1)"], "NIST": ["CP-9"]},
    "RDS Minor Upgrade":           {"CIS": ["2.3.3"], "PCI": ["6.3.3"], "SOC2": ["CC7.1"], "NIST": ["SI-2"]},
    # Secrets / KMS
    "Secrets Manager Rotation":    {"PCI": ["8.6.1"], "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)"], "NIST": ["IA-5", "SC-12"]},
    "KMS Key Policy":              {"CIS": ["3.8"], "PCI": ["4.2.1"], "SOC2": ["CC6.7"], "HIPAA": ["164.312(e)(2)"], "NIST": ["SC-12"]},
    # GuardDuty / Security Hub
    "GuardDuty Enabled":           {"PCI": ["11.3.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.308(a)(1)"], "NIST": ["SI-4", "RA-5"]},
    "Security Hub Enabled":        {"PCI": ["11.3.1"], "SOC2": ["CC7.2"], "NIST": ["RA-5"]},
    "Security Hub Finding":        {"PCI": ["11.3.1"], "SOC2": ["CC7.3"], "NIST": ["SI-4", "RA-5"]},
    # Config / CloudWatch
    "AWS Config Enabled":          {"CIS": ["3.5"], "PCI": ["10.2.1"], "SOC2": ["CC7.1"], "NIST": ["CM-8"]},
    "CloudWatch Alarm":            {"CIS": ["4.1","4.2","4.3","4.4","4.5","4.6","4.7","4.8","4.9","4.10"], "PCI": ["10.7.1"], "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "NIST": ["AU-12", "SI-4"]},
    # Cost / misc
    "Idle Resource":               {"SOC2": ["CC9.1"], "NIST": ["CM-8"]},
    "Unattached Volume":           {"SOC2": ["CC9.1"], "NIST": ["CM-8"]},
    "Reserved Instance":           {"SOC2": ["CC9.1"]},
}

ALL_FRAMEWORKS = {
    "CIS":   CIS_CONTROLS,
    "PCI":   PCI_CONTROLS,
    "SOC2":  SOC2_CONTROLS,
    "HIPAA": HIPAA_CONTROLS,
    "NIST":  NIST_CONTROLS,
}

FRAMEWORK_NAMES = {
    "CIS":   "CIS AWS Benchmarks v1.5",
    "PCI":   "PCI-DSS v4.0",
    "SOC2":  "SOC 2 (TSC 2017)",
    "HIPAA": "HIPAA Security Rule",
    "NIST":  "NIST SP 800-53 Rev 5",
}


def enrich_finding(check_name: str, existing_compliance: dict | None = None) -> dict:
    """Return a merged compliance dict for a finding, adding any missing framework controls."""
    base = dict(existing_compliance or {})
    mapping = FINDING_CONTROL_MAP.get(check_name, {})
    for fw, ctrl_ids in mapping.items():
        if fw not in base:
            base[fw] = ", ".join(ctrl_ids)
    return base


def score_compliance(findings: list[dict]) -> dict[str, dict]:
    """
    Calculate pass/fail/score per compliance framework across a list of findings.
    Returns:
        {
          "CIS": { "score": 72, "pass": 45, "fail": 17, "controls": { "1.4": "FAIL", ... } },
          ...
        }
    """
    results: dict[str, dict] = {
        fw: {"score": 0, "pass": 0, "fail": 0, "controls": {}} for fw in ALL_FRAMEWORKS
    }

    for finding in findings:
        check = finding.get("check_name", "")
        status = finding.get("status", "")
        mapping = FINDING_CONTROL_MAP.get(check, {})
        passed = status in ("PASS", "pass")

        for fw, ctrl_ids in mapping.items():
            for ctrl_id in ctrl_ids:
                current = results[fw]["controls"].get(ctrl_id)
                # Once failed, stays failed
                if current != "FAIL":
                    results[fw]["controls"][ctrl_id] = "PASS" if passed else "FAIL"

    for fw, data in results.items():
        ctrl = data["controls"]
        passed = sum(1 for v in ctrl.values() if v == "PASS")
        failed = sum(1 for v in ctrl.values() if v == "FAIL")
        total = passed + failed
        data["pass"] = passed
        data["fail"] = failed
        data["score"] = round(passed / total * 100) if total > 0 else 0
        data["total_controls"] = total

    return results


def get_control_details(framework: str, control_id: str) -> dict:
    """Return the title + section for a specific control."""
    fw_map = ALL_FRAMEWORKS.get(framework, {})
    return fw_map.get(control_id, {"title": control_id, "section": "Unknown"})
