import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, ForeignKey, ARRAY, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class AwsConfig(Base):
    __tablename__ = "aws_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    deployer_role_arn = Column(Text, nullable=False)
    deployer_external_id = Column(Text, nullable=False)
    audit_role_name = Column(Text, nullable=False, default="AuditRole")
    audit_role_external_id = Column(Text, nullable=False)
    regions = Column(ARRAY(Text), nullable=False, default=lambda: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"])
    use_organizations = Column(Boolean, default=False)
    enabled_audits = Column(ARRAY(Text), nullable=False, default=lambda: ["iam", "network", "exposure", "cloudtrail", "security_hub", "cost_optimization", "cyber"])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AwsAccount(Base):
    __tablename__ = "aws_accounts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    account_id = Column(Text, nullable=False)
    account_name = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditJob(Base):
    __tablename__ = "audit_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    status = Column(Text, nullable=False, default="pending")  # pending | running | completed | failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    accounts_audited = Column(ARRAY(Text), default=lambda: [])
    total_findings = Column(Integer, default=0)
    error_message = Column(Text)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("audit_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    account_id = Column(Text, nullable=False)
    region = Column(Text, default="")
    service = Column(Text, default="")
    check_name = Column(Text, default="")
    status = Column(Text, default="")
    severity = Column(Text, default="Low")
    finding_type = Column(Text, default="")
    details = Column(Text, default="")
    recommendation = Column(Text, default="")
    timestamp = Column(DateTime)
    compliance = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    # AI-generated remediation (populated on demand)
    ai_remediation = Column(JSONB, nullable=True)


class AiAnalysis(Base):
    """Stores LLM-generated analysis for a completed audit job."""
    __tablename__ = "ai_analyses"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("audit_jobs.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    headline = Column(Text, default="")
    risk_level = Column(Text, default="")
    summary = Column(Text, default="")
    top_risks = Column(ARRAY(Text), default=lambda: [])
    quick_wins = Column(ARRAY(Text), default=lambda: [])
    narrative = Column(Text, default="")
    executive_report = Column(Text, nullable=True)
    raw_response = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ComplianceScore(Base):
    """Per-framework compliance scores for an audit job."""
    __tablename__ = "compliance_scores"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("audit_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    framework = Column(Text, nullable=False)       # CIS | PCI | SOC2 | HIPAA | NIST
    score = Column(Float, default=0.0)             # 0–100
    pass_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)
    total_controls = Column(Integer, default=0)
    controls_detail = Column(JSONB, default=dict)  # { "1.4": "PASS", "1.5": "FAIL", ... }
    created_at = Column(DateTime, default=datetime.utcnow)
