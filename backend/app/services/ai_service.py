"""
Ollama-backed AI service for findings analysis, remediation generation,
natural language chat, and executive compliance report generation.
"""

from __future__ import annotations
import os
import json
import logging
from typing import AsyncIterator

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
TIMEOUT = 120.0  # seconds — local models can be slow on first run


def _chat_body(messages: list[dict], stream: bool = False) -> dict:
    return {"model": DEFAULT_MODEL, "messages": messages, "stream": stream}


async def _complete(messages: list[dict]) -> str:
    """Single non-streaming completion via Ollama /api/chat."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{OLLAMA_BASE}/api/chat",
            json=_chat_body(messages, stream=False),
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


async def stream_chat(messages: list[dict]) -> AsyncIterator[str]:
    """Streaming generator for the chat endpoint — yields text chunks."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        async with client.stream(
            "POST",
            f"{OLLAMA_BASE}/api/chat",
            json=_chat_body(messages, stream=True),
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue


def _findings_snippet(findings: list[dict], max_findings: int = 40) -> str:
    """Compact representation of findings for LLM context."""
    rows = []
    for f in findings[:max_findings]:
        rows.append(
            f"[{f.get('severity','?')}] {f.get('service','?')} / {f.get('check_name','?')} "
            f"({f.get('status','?')}) — {f.get('details','')[:120]}"
        )
    return "\n".join(rows)


# ── Public API ────────────────────────────────────────────────────────────────

async def analyze_findings(findings: list[dict], account_ids: list[str]) -> dict:
    """
    Analyse a set of audit findings and return structured risk narrative.
    Returns: { headline, risk_level, summary, top_risks, quick_wins, narrative }
    """
    snippet = _findings_snippet(findings)
    counts = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1

    system = (
        "You are a senior AWS cloud security engineer. "
        "Analyse the provided findings and respond ONLY with valid JSON. "
        "Do not include any text outside the JSON object."
    )
    user = f"""Accounts audited: {', '.join(account_ids)}
Findings summary: {json.dumps(counts)}
Top findings:
{snippet}

Respond with this exact JSON schema:
{{
  "headline": "<one sentence executive summary>",
  "risk_level": "<Critical|High|Medium|Low>",
  "summary": "<2-3 sentence plain-English summary of the overall security posture>",
  "top_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "quick_wins": ["<quick fix 1>", "<quick fix 2>", "<quick fix 3>"],
  "narrative": "<3-4 paragraph detailed analysis covering IAM, network, data, and logging posture>"
}}"""

    raw = await _complete([
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ])

    # Strip markdown code fences if model wraps output
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("AI analysis returned non-JSON: %s", raw[:200])
        return {
            "headline": "Analysis complete",
            "risk_level": "Unknown",
            "summary": raw[:500],
            "top_risks": [],
            "quick_wins": [],
            "narrative": raw,
        }


async def generate_remediation(finding: dict) -> dict:
    """
    Generate concrete remediation steps + CLI/Terraform/CloudFormation scripts
    for a single finding.
    Returns: { steps, cli_script, terraform_snippet, explanation }
    """
    system = (
        "You are an AWS security engineer specialising in automated remediation. "
        "Respond ONLY with valid JSON. No markdown outside the JSON."
    )
    user = f"""Finding to remediate:
Service: {finding.get('service')}
Check: {finding.get('check_name')}
Severity: {finding.get('severity')}
Details: {finding.get('details')}
Recommendation: {finding.get('recommendation')}
Account: {finding.get('account_id')}
Region: {finding.get('region')}

Respond with this exact JSON:
{{
  "explanation": "<Why this is a risk and what the fix achieves>",
  "steps": ["<step 1>", "<step 2>", "<step 3>"],
  "cli_script": "<AWS CLI commands to remediate, one per line, with comments>",
  "terraform_snippet": "<Terraform HCL snippet that enforces the correct configuration or empty string>",
  "estimated_effort": "<5 minutes|30 minutes|2 hours|1 day>",
  "risk_if_not_fixed": "<brief description of exploitation scenario>"
}}"""

    raw = await _complete([
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ])

    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith(("json", "hcl")):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "explanation": finding.get("recommendation", ""),
            "steps": [raw[:500]],
            "cli_script": "",
            "terraform_snippet": "",
            "estimated_effort": "Unknown",
            "risk_if_not_fixed": "",
        }


async def chat_with_findings(
    question: str,
    findings: list[dict],
    history: list[dict] | None = None,
) -> AsyncIterator[str]:
    """
    Stream an answer to a natural language question about the audit findings.
    history: list of {"role": "user"|"assistant", "content": "..."}
    """
    snippet = _findings_snippet(findings, max_findings=50)
    system = (
        "You are an expert AWS cloud security analyst. "
        "Answer questions about the provided audit findings concisely and accurately. "
        "Always ground your answers in the specific findings provided. "
        "If asked for remediation, give concrete AWS CLI or console steps."
    )
    context_msg = {
        "role": "user",
        "content": f"Here are the current audit findings:\n\n{snippet}\n\nPlease keep this context in mind for my questions.",
    }
    ack_msg = {
        "role": "assistant",
        "content": "Understood. I have reviewed the audit findings and am ready to answer your questions.",
    }

    messages = [
        {"role": "system", "content": system},
        context_msg,
        ack_msg,
    ]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": question})

    async for token in stream_chat(messages):
        yield token


async def generate_executive_report(
    summary: dict,
    findings: list[dict],
    compliance_scores: dict,
    account_ids: list[str],
) -> str:
    """
    Generate a board-ready executive compliance report in Markdown.
    summary: { total, by_severity, by_service }
    compliance_scores: output of compliance_mapper.score_compliance()
    """
    sev_counts = summary.get("by_severity", {})
    framework_lines = "\n".join(
        f"- {fw}: {data['score']}% ({data['pass']} pass / {data['fail']} fail)"
        for fw, data in compliance_scores.items()
    )
    snippet = _findings_snippet(findings, max_findings=30)

    system = (
        "You are a senior cybersecurity consultant writing a board-level compliance report. "
        "Write in clear, professional business language. Use Markdown formatting with headers, "
        "bullet points, and emphasis. The report should be suitable for C-suite and auditors."
    )
    user = f"""Write a comprehensive executive compliance report for the following AWS audit results.

Accounts audited: {', '.join(account_ids)}
Total findings: {summary.get('total', 0)}
Severity breakdown: {json.dumps(sev_counts)}

Compliance framework scores:
{framework_lines}

Sample findings (top {min(30, len(findings))}):
{snippet}

Structure the report with these sections:
1. Executive Summary
2. Risk Overview
3. Compliance Posture (one paragraph per framework)
4. Critical and High Priority Issues
5. Recommendations and Remediation Roadmap
6. Conclusion

Make it actionable, specific to AWS, and reference the actual findings. Approximately 800-1200 words."""

    return await _complete([
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ])


async def check_ollama_health() -> dict:
    """Check if Ollama is running and the configured model is available."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            model_available = any(DEFAULT_MODEL in m for m in models)
            return {
                "status": "ok",
                "ollama_url": OLLAMA_BASE,
                "model": DEFAULT_MODEL,
                "model_available": model_available,
                "available_models": models,
            }
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "ollama_url": OLLAMA_BASE,
            "model": DEFAULT_MODEL,
            "model_available": False,
        }
