"""
Background audit execution for Streamlit — runs in a daemon thread so the UI stays responsive.
Reuses the existing auditor/ modules unchanged.
"""
from __future__ import annotations
import logging
import sys
import os
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Ensure project root is on the path
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _assume_role(sts_client, role_arn: str, session_name: str, external_id: str = ""):
    """Assume an IAM role and return a boto3 Session."""
    import boto3
    kwargs: dict = {"RoleArn": role_arn, "RoleSessionName": session_name}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts_client.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def run_audit(job_id: str, user_id: str, config: dict, account_ids: list[str]):
    """
    Entry point — call this in a background thread.
    Updates the audit_jobs row in Supabase as it progresses.
    """
    # Import db inside the thread to avoid Streamlit context issues
    import sys as _sys, os as _os
    _lib = _os.path.dirname(_os.path.abspath(__file__))
    if _lib not in _sys.path:
        _sys.path.insert(0, _lib)
    import db as _db

    try:
        import boto3
        from auditor.modules.orchestrator import run_all_audits

        _db.update_audit_job(job_id, {
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

        all_findings: list[dict] = []
        audited: list[str] = []

        # Build deployer session — read creds from env or Streamlit secrets
        def _get_secret(key: str) -> str | None:
            try:
                import streamlit as _st
                parts = key.split(".")
                obj = _st.secrets
                for part in parts:
                    obj = obj[part]
                return str(obj) or None
            except Exception:
                return os.environ.get(key.split(".")[-1].upper()) or None

        aws_key = os.environ.get("AWS_ACCESS_KEY_ID") or _get_secret("aws.AWS_ACCESS_KEY_ID")
        aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY") or _get_secret("aws.AWS_SECRET_ACCESS_KEY")

        app_sts = boto3.client(
            "sts",
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            region_name=config.get("regions", ["us-east-1"])[0],
        )
        deployer_session = _assume_role(
            app_sts,
            config["deployer_role_arn"],
            "StreamlitAuditDeployer",
            config.get("deployer_external_id", ""),
        )

        # Resolve account list
        if config.get("use_organizations"):
            org = deployer_session.client("organizations", region_name="us-east-1")
            paginator = org.get_paginator("list_accounts")
            account_ids = [a["Id"] for page in paginator.paginate() for a in page["Accounts"] if a["Status"] == "ACTIVE"]

        regions: list[str] = config.get("regions") or ["us-east-1"]
        audit_cfg = {"enabled_audits": config.get("enabled_audits") or list()}

        for acct_id in account_ids:
            try:
                acct_session = _assume_role(
                    deployer_session.client("sts"),
                    f"arn:aws:iam::{acct_id}:role/{config['audit_role_name']}",
                    "StreamlitAuditSession",
                    config.get("audit_role_external_id", ""),
                )
                findings = run_all_audits(acct_id, acct_session, regions, audit_cfg)
                all_findings.extend(findings)
                audited.append(acct_id)
                logger.info("Audited account %s: %d findings", acct_id, len(findings))
            except Exception as exc:
                logger.error("Account %s failed: %s", acct_id, exc)

        # Save findings
        _db.save_findings(job_id, user_id, all_findings)

        # Mark complete
        _db.update_audit_job(job_id, {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "accounts_audited": audited,
            "total_findings": len(all_findings),
        })

    except Exception as exc:
        logger.error("Audit job %s failed: %s", job_id, exc)
        try:
            _db2 = _db
            _db2.update_audit_job(job_id, {
                "status": "failed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": str(exc)[:500],
            })
        except Exception:
            pass


def start_audit(job_id: str, user_id: str, config: dict, account_ids: list[str]):
    """Launch audit in a daemon thread."""
    t = threading.Thread(
        target=run_audit,
        args=(job_id, user_id, config, account_ids),
        daemon=True,
        name=f"audit-{job_id[:8]}",
    )
    t.start()
    return t
