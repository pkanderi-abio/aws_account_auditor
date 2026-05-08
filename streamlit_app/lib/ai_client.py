"""
Synchronous Ollama client for Streamlit.
All functions return gracefully if Ollama is unavailable (e.g. on Streamlit Cloud).
"""
from __future__ import annotations
import json
import os
import logging

import requests

logger = logging.getLogger(__name__)

OLLAMA_BASE  = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
TIMEOUT = 180


def is_available() -> tuple[bool, str]:
    """Returns (available, model_name_or_error)."""
    try:
        resp = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        if any(DEFAULT_MODEL in m for m in models):
            return True, DEFAULT_MODEL
        if models:
            return False, f"Model '{DEFAULT_MODEL}' not found. Available: {', '.join(models)}"
        return False, "No models pulled yet. Run: ollama pull llama3.2"
    except Exception as exc:
        return False, f"Ollama not running at {OLLAMA_BASE}: {exc}"


def _complete(messages: list[dict]) -> str:
    resp = requests.post(
        f"{OLLAMA_BASE}/api/chat",
        json={"model": DEFAULT_MODEL, "messages": messages, "stream": False},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _findings_snippet(findings: list[dict], n: int = 40) -> str:
    rows = []
    for f in findings[:n]:
        rows.append(
            f"[{f.get('severity','?')}] {f.get('service','?')} / {f.get('check_name','?')} "
            f"({f.get('status','?')}) — {f.get('details','')[:120]}"
        )
    return "\n".join(rows)


def analyze_findings(findings: list[dict], account_ids: list[str]) -> dict:
    snippet = _findings_snippet(findings)
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "?")
        counts[sev] = counts.get(sev, 0) + 1

    system = (
        "You are a senior AWS cloud security engineer. "
        "Analyse the provided findings and respond ONLY with valid JSON. "
        "Do not include any text outside the JSON object."
    )
    user = f"""Accounts audited: {', '.join(account_ids)}
Severity counts: {json.dumps(counts)}
Findings (sample):
{snippet}

Respond with this EXACT JSON:
{{
  "headline": "<one-sentence executive summary>",
  "risk_level": "<Critical|High|Medium|Low>",
  "summary": "<2-3 sentence overview>",
  "top_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "quick_wins": ["<fix 1>", "<fix 2>", "<fix 3>"],
  "narrative": "<3-4 paragraph analysis covering IAM, network, data, logging posture>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except Exception:
        return {"headline": "Analysis complete", "risk_level": "Unknown", "summary": raw[:400],
                "top_risks": [], "quick_wins": [], "narrative": raw}


def generate_remediation(finding: dict) -> dict:
    system = (
        "You are an AWS security engineer. "
        "Respond ONLY with valid JSON. No text outside the JSON object."
    )
    user = f"""Finding:
Service: {finding.get('service')}  Check: {finding.get('check_name')}
Severity: {finding.get('severity')}  Details: {finding.get('details')}
Recommendation: {finding.get('recommendation')}
Account: {finding.get('account_id')}  Region: {finding.get('region')}

Respond with:
{{
  "explanation": "<why this is a risk>",
  "steps": ["<step 1>", "<step 2>"],
  "cli_script": "<AWS CLI commands with comments>",
  "terraform_snippet": "<Terraform HCL or empty string>",
  "estimated_effort": "<5 minutes|30 minutes|2 hours|1 day>",
  "risk_if_not_fixed": "<exploitation scenario>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith(("json", "hcl")):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except Exception:
        return {"explanation": finding.get("recommendation", ""),
                "steps": [raw[:300]], "cli_script": "", "terraform_snippet": "",
                "estimated_effort": "Unknown", "risk_if_not_fixed": ""}


def chat(question: str, findings: list[dict], history: list[dict] | None = None) -> str:
    snippet = _findings_snippet(findings, n=50)
    system = (
        "You are an expert AWS cloud security analyst. "
        "Answer questions about the provided audit findings concisely and accurately. "
        "Always ground answers in the specific findings provided."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Here are the current audit findings:\n\n{snippet}\n\nUse this context for my questions."},
        {"role": "assistant", "content": "Understood. I have reviewed the audit findings and am ready to answer your questions."},
    ]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": question})
    return _complete(messages)


def generate_executive_report(summary: dict, findings: list[dict], compliance_scores: dict, account_ids: list[str]) -> str:
    framework_lines = "\n".join(
        f"- {fw}: {data['score']}% ({data['pass']} pass / {data['fail']} fail)"
        for fw, data in compliance_scores.items()
    )
    snippet = _findings_snippet(findings, n=30)
    system = (
        "You are a senior cybersecurity consultant writing a board-level compliance report. "
        "Write in clear, professional Markdown with headers and bullet points."
    )
    user = f"""Write an executive compliance report for the following AWS audit.

Accounts: {', '.join(account_ids)}
Total findings: {summary.get('total', 0)}
Severity: {json.dumps(summary.get('by_severity', {}))}
Compliance scores:
{framework_lines}
Sample findings:
{snippet}

Sections: 1. Executive Summary  2. Risk Overview  3. Compliance Posture (per framework)
4. Critical/High Issues  5. Remediation Roadmap  6. Conclusion.
~800-1200 words, actionable and specific to AWS."""

    return _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
