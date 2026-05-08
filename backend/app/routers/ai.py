"""
AI-powered endpoints:
  POST /api/ai/analyze/{job_id}       — run LLM analysis on a completed job
  GET  /api/ai/analysis/{job_id}      — fetch stored analysis
  POST /api/ai/remediate/{finding_id} — generate remediation for one finding
  POST /api/ai/report/{job_id}        — generate executive compliance report
  POST /api/ai/chat/{job_id}          — streaming chat (SSE)
  GET  /api/ai/health                 — Ollama connectivity check
  GET  /api/compliance/{job_id}       — per-framework compliance scores
"""

from __future__ import annotations
import uuid
import json
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.auth import get_current_user
from app.database import get_db
from app.models import AuditJob, Finding, AiAnalysis, ComplianceScore
from app.services import ai_service, compliance_mapper

router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _require_job(job_id: str, user_id: str, db: AsyncSession) -> AuditJob:
    job = await db.get(AuditJob, UUID(job_id))
    if not job or str(job.user_id) != user_id:
        raise HTTPException(status_code=404, detail="Audit job not found")
    return job


async def _get_findings(job_id: str, db: AsyncSession) -> list[dict]:
    rows = (await db.scalars(
        select(Finding).where(Finding.job_id == UUID(job_id))
    )).all()
    return [
        {
            "id": str(f.id),
            "account_id": f.account_id,
            "region": f.region,
            "service": f.service,
            "check_name": f.check_name,
            "status": f.status,
            "severity": f.severity,
            "finding_type": f.finding_type,
            "details": f.details,
            "recommendation": f.recommendation,
            "compliance": f.compliance or {},
        }
        for f in rows
    ]


# ── Ollama health ─────────────────────────────────────────────────────────────

@router.get("/health")
async def ollama_health():
    return await ai_service.check_ollama_health()


# ── Findings analysis ─────────────────────────────────────────────────────────

@router.post("/analyze/{job_id}")
async def analyze_job(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run LLM analysis on all findings for a completed audit job."""
    job = await _require_job(job_id, user_id, db)
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Job is not completed yet")

    findings = await _get_findings(job_id, db)
    if not findings:
        raise HTTPException(status_code=400, detail="No findings to analyse")

    result = await ai_service.analyze_findings(findings, job.accounts_audited or [])

    # Upsert analysis record
    existing = (await db.scalars(
        select(AiAnalysis).where(AiAnalysis.job_id == UUID(job_id))
    )).first()

    if existing:
        existing.headline = result.get("headline", "")
        existing.risk_level = result.get("risk_level", "")
        existing.summary = result.get("summary", "")
        existing.top_risks = result.get("top_risks", [])
        existing.quick_wins = result.get("quick_wins", [])
        existing.narrative = result.get("narrative", "")
        existing.raw_response = result
    else:
        db.add(AiAnalysis(
            job_id=UUID(job_id),
            user_id=UUID(user_id),
            headline=result.get("headline", ""),
            risk_level=result.get("risk_level", ""),
            summary=result.get("summary", ""),
            top_risks=result.get("top_risks", []),
            quick_wins=result.get("quick_wins", []),
            narrative=result.get("narrative", ""),
            raw_response=result,
        ))
    await db.commit()
    return result


@router.get("/analysis/{job_id}")
async def get_analysis(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch stored LLM analysis for a job (or 404 if not generated yet)."""
    await _require_job(job_id, user_id, db)
    analysis = (await db.scalars(
        select(AiAnalysis).where(AiAnalysis.job_id == UUID(job_id))
    )).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not generated yet — call POST /analyze first")
    return {
        "headline": analysis.headline,
        "risk_level": analysis.risk_level,
        "summary": analysis.summary,
        "top_risks": analysis.top_risks or [],
        "quick_wins": analysis.quick_wins or [],
        "narrative": analysis.narrative,
        "executive_report": analysis.executive_report,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }


# ── Per-finding remediation ───────────────────────────────────────────────────

@router.post("/remediate/{finding_id}")
async def remediate_finding(
    finding_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate and cache AI remediation for a single finding."""
    finding = await db.get(Finding, UUID(finding_id))
    if not finding or str(finding.user_id) != user_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Return cached result if available
    if finding.ai_remediation:
        return finding.ai_remediation

    result = await ai_service.generate_remediation({
        "service": finding.service,
        "check_name": finding.check_name,
        "severity": finding.severity,
        "details": finding.details,
        "recommendation": finding.recommendation,
        "account_id": finding.account_id,
        "region": finding.region,
    })

    finding.ai_remediation = result
    await db.commit()
    return result


# ── Executive report ──────────────────────────────────────────────────────────

@router.post("/report/{job_id}")
async def generate_report(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate (or regenerate) an executive compliance report for a job."""
    job = await _require_job(job_id, user_id, db)
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Job is not completed yet")

    findings = await _get_findings(job_id, db)

    # Compute compliance scores for context
    scores = compliance_mapper.score_compliance(findings)

    sev_counts: dict[str, int] = {}
    svc_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        svc_counts[f["service"]] = svc_counts.get(f["service"], 0) + 1

    summary = {"total": len(findings), "by_severity": sev_counts, "by_service": svc_counts}

    report_md = await ai_service.generate_executive_report(
        summary, findings, scores, job.accounts_audited or []
    )

    # Store in AiAnalysis
    analysis = (await db.scalars(
        select(AiAnalysis).where(AiAnalysis.job_id == UUID(job_id))
    )).first()
    if analysis:
        analysis.executive_report = report_md
    else:
        db.add(AiAnalysis(
            job_id=UUID(job_id),
            user_id=UUID(user_id),
            executive_report=report_md,
        ))
    await db.commit()

    return {"report": report_md}


# ── Streaming chat ────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    question: str
    history: Optional[list[dict]] = None


@router.post("/chat/{job_id}")
async def chat(
    job_id: str,
    body: ChatRequest,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Stream an AI answer to a natural language question about the audit findings.
    Returns text/event-stream (SSE).
    """
    await _require_job(job_id, user_id, db)
    findings = await _get_findings(job_id, db)

    async def event_stream():
        async for token in ai_service.chat_with_findings(
            body.question, findings, body.history
        ):
            yield f"data: {json.dumps({'token': token})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Compliance scores ─────────────────────────────────────────────────────────

@router.get("/compliance/{job_id}")
async def get_compliance_scores(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compute and return compliance scores for all frameworks.
    Recomputes on each call from the live findings (fast, no LLM required).
    """
    await _require_job(job_id, user_id, db)
    findings = await _get_findings(job_id, db)
    scores = compliance_mapper.score_compliance(findings)

    # Persist latest scores
    existing_scores = (await db.scalars(
        select(ComplianceScore).where(ComplianceScore.job_id == UUID(job_id))
    )).all()
    existing_by_fw = {s.framework: s for s in existing_scores}

    for fw, data in scores.items():
        if fw in existing_by_fw:
            rec = existing_by_fw[fw]
            rec.score = data["score"]
            rec.pass_count = data["pass"]
            rec.fail_count = data["fail"]
            rec.total_controls = data["total_controls"]
            rec.controls_detail = data["controls"]
        else:
            db.add(ComplianceScore(
                job_id=UUID(job_id),
                user_id=UUID(user_id),
                framework=fw,
                score=data["score"],
                pass_count=data["pass"],
                fail_count=data["fail"],
                total_controls=data["total_controls"],
                controls_detail=data["controls"],
            ))
    await db.commit()

    return {
        fw: {
            "framework_name": compliance_mapper.FRAMEWORK_NAMES.get(fw, fw),
            "score": data["score"],
            "pass": data["pass"],
            "fail": data["fail"],
            "total_controls": data["total_controls"],
            "controls": data["controls"],
        }
        for fw, data in scores.items()
    }
