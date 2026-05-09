"""
AI client — Groq (free, cloud) preferred; falls back to Ollama (local).
Set GROQ_API_KEY in Streamlit secrets or environment to enable cloud AI.
"""
from __future__ import annotations
import json
import os
import logging

import requests

logger = logging.getLogger(__name__)

# ── Groq ──────────────────────────────────────────────────────────────────────
GROQ_BASE  = "https://api.groq.com/openai/v1"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_BASE   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL", "llama3.2")
TIMEOUT = 120


def _groq_key() -> str:
    """Read Groq API key — checks env, all secret locations, and common TOML mistakes."""
    if os.environ.get("GROQ_API_KEY"):
        return os.environ["GROQ_API_KEY"]
    try:
        import streamlit as st
        for path in (
            ("GROQ_API_KEY",),          # top-level (correct placement)
            ("aws", "GROQ_API_KEY"),    # under [aws] section (common TOML mistake)
            ("groq", "api_key"),        # under [groq] section
            ("groq", "GROQ_API_KEY"),
        ):
            try:
                obj = st.secrets
                for part in path:
                    obj = obj[part]
                val = str(obj).strip()
                if val:
                    return val
            except (KeyError, AttributeError):
                continue
    except Exception:
        pass
    return ""


def is_available() -> tuple[bool, str]:
    """Returns (available, description). Prefers Groq over Ollama."""
    # Try Groq first
    key = _groq_key()
    if key:
        try:
            r = requests.get(f"{GROQ_BASE}/models",
                             headers={"Authorization": f"Bearer {key}"}, timeout=5)
            if r.status_code == 200:
                return True, f"Groq · {GROQ_MODEL}"
        except Exception:
            pass
        return False, "Groq API key set but unreachable"

    # Fall back to Ollama
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        if any(OLLAMA_MODEL in m for m in models):
            return True, f"Ollama · {OLLAMA_MODEL}"
        if models:
            return False, f"Ollama running but model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}"
        return False, "Ollama running but no models pulled"
    except Exception:
        return False, "No AI available. Add GROQ_API_KEY to Streamlit secrets (free at console.groq.com)"


def _complete(messages: list[dict]) -> str:
    """Send chat messages and return the reply text."""
    key = _groq_key()
    if key:
        r = requests.post(
            f"{GROQ_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": GROQ_MODEL, "messages": messages, "temperature": 0.3},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    # Ollama fallback
    r = requests.post(
        f"{OLLAMA_BASE}/api/chat",
        json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def _findings_snippet(findings: list[dict], n: int = 60) -> str:
    rows = []
    for f in findings[:n]:
        rows.append(
            f"[{f.get('severity','?')}][{f.get('status','?')}] "
            f"{f.get('service','?')} / {f.get('check_name','?')} "
            f"account={f.get('account_id','')} region={f.get('region','')} — "
            f"{f.get('details','')[:150]}"
        )
    return "\n".join(rows)


def _group_findings(findings: list[dict]) -> dict:
    """Return counts grouped by severity and service for richer prompt context."""
    by_sev: dict[str, int] = {}
    by_svc: dict[str, int] = {}
    by_check: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "?")
        svc = f.get("service", "?")
        chk = f.get("check_name", "?")
        by_sev[s] = by_sev.get(s, 0) + 1
        by_svc[svc] = by_svc.get(svc, 0) + 1
        by_check[chk] = by_check.get(chk, 0) + 1
    top_checks = sorted(by_check.items(), key=lambda x: -x[1])[:10]
    return {"by_severity": by_sev, "by_service": by_svc, "top_failing_checks": top_checks}


def _clean_json(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        parts = cleaned.split("```")
        cleaned = parts[1] if len(parts) > 1 else cleaned
        if cleaned.startswith(("json", "hcl")):
            cleaned = cleaned[4:]
    return cleaned.strip()


def analyze_findings(findings: list[dict], account_ids: list[str]) -> dict:
    stats = _group_findings(findings)
    snippet = _findings_snippet(findings, n=60)

    system = (
        "You are a senior AWS cloud security engineer and compliance expert. "
        "Analyse audit findings and respond ONLY with valid JSON — no text outside the JSON object. "
        "Be specific: reference actual service names, check names, and account IDs from the data. "
        "For every top risk and quick win, include a concrete AWS CLI command or CloudFormation snippet."
    )
    user = f"""Accounts audited: {', '.join(account_ids)}
Severity breakdown: {json.dumps(stats['by_severity'])}
Top failing checks: {json.dumps(stats['top_failing_checks'])}
Services affected: {json.dumps(stats['by_service'])}
Total findings: {len(findings)}

Detailed findings (up to 60):
{snippet}

Respond with this EXACT JSON — be specific, actionable, and reference real check names/accounts:
{{
  "headline": "<one-sentence executive summary citing the most critical finding>",
  "risk_level": "<Critical|High|Medium|Low>",
  "summary": "<3-4 sentence overview naming the top 2-3 issues found and their business impact>",
  "top_risks": [
    "<Risk 1: service/check name — specific impact and blast radius>",
    "<Risk 2: ...>",
    "<Risk 3: ...>",
    "<Risk 4: ...>",
    "<Risk 5: ...>"
  ],
  "quick_wins": [
    "<Fix 1: specific action with CLI command, e.g.: Enable CloudTrail: aws cloudtrail create-trail --name mgmt-events --s3-bucket-name cloudtrail-logs-ACCOUNT --is-multi-region-trail && aws cloudtrail start-logging --name mgmt-events>",
    "<Fix 2: ...>",
    "<Fix 3: ...>",
    "<Fix 4: ...>",
    "<Fix 5: ...>"
  ],
  "narrative": "<4-5 paragraph deep-dive. Para 1: logging/CloudTrail posture with specific missing trails. Para 2: IAM posture — MFA gaps, unused credentials, over-privileged roles. Para 3: network exposure — open security groups, public resources. Para 4: data security — unencrypted S3, RDS, EBS. Para 5: compliance gaps and recommended remediation priority order. Include at least 3 specific AWS CLI commands or CloudFormation resource types.>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    try:
        return json.loads(_clean_json(raw))
    except Exception:
        return {"headline": "Analysis complete", "risk_level": "Unknown", "summary": raw[:400],
                "top_risks": [], "quick_wins": [], "narrative": raw}


def generate_remediation(finding: dict) -> dict:
    account = finding.get('account_id', 'YOUR_ACCOUNT')
    region  = finding.get('region', 'us-east-1')
    service = finding.get('service', '')
    check   = finding.get('check_name', '')

    system = (
        "You are an AWS security engineer. "
        "Respond ONLY with valid JSON. No text outside the JSON object. "
        "CLI commands must be real, copy-paste ready AWS CLI v2 commands. "
        "Terraform must be valid HCL. CloudFormation snippets must be valid YAML."
    )
    user = f"""Finding to remediate:
Service: {service}
Check: {check}
Severity: {finding.get('severity')}
Status: {finding.get('status')}
Details: {finding.get('details')}
Recommendation: {finding.get('recommendation')}
Account ID: {account}
Region: {region}

Provide specific remediation — use the real account ID and region in commands.
For CloudTrail findings, include the full aws cloudtrail create-trail command.
For IAM findings, include the exact aws iam command.
For S3 findings, include the bucket name from details if present.

Respond with:
{{
  "explanation": "<2-3 sentences on why this specific finding is dangerous and what an attacker gains>",
  "steps": [
    "<Step 1: concrete action with exact console path or CLI command>",
    "<Step 2: ...>",
    "<Step 3: verify — command to confirm the fix worked>"
  ],
  "cli_script": "#!/bin/bash\\n# Remediate: {check}\\n# Account: {account} / Region: {region}\\n\\n<full script with set -euo pipefail, real commands, and verification step>",
  "cloudformation_snippet": "<YAML CloudFormation resource block that enforces the fix, or empty string>",
  "terraform_snippet": "<Terraform HCL resource block that enforces the fix, or empty string>",
  "estimated_effort": "<5 minutes|30 minutes|2 hours|1 day>",
  "risk_if_not_fixed": "<specific exploitation scenario with attacker steps>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    try:
        return json.loads(_clean_json(raw))
    except Exception:
        return {"explanation": finding.get("recommendation", ""),
                "steps": [raw[:300]], "cli_script": "", "cloudformation_snippet": "",
                "terraform_snippet": "", "estimated_effort": "Unknown", "risk_if_not_fixed": ""}


def chat(question: str, findings: list[dict], history: list[dict] | None = None) -> str:
    stats = _group_findings(findings)
    snippet = _findings_snippet(findings, n=60)
    system = (
        "You are an expert AWS cloud security analyst. "
        "Answer questions about the provided audit findings with specific, actionable advice. "
        "Always cite the exact finding (service/check name) and include CLI commands or "
        "CloudFormation/Terraform snippets when recommending fixes. "
        "Reference actual account IDs and regions from the findings data."
    )
    context = (
        f"Audit findings context:\n"
        f"Severity counts: {json.dumps(stats['by_severity'])}\n"
        f"Top failing checks: {json.dumps(stats['top_failing_checks'])}\n\n"
        f"Detailed findings:\n{snippet}"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": context},
        {"role": "assistant", "content": "Understood — I have reviewed all audit findings including severity breakdowns, failing checks, and account/region details. Ready for your questions."},
    ]
    if history:
        messages.extend(history[-10:])
    messages.append({"role": "user", "content": question})
    return _complete(messages)


def generate_executive_report(summary: dict, findings: list[dict], compliance_scores: dict, account_ids: list[str]) -> str:
    stats = _group_findings(findings)
    framework_lines = "\n".join(
        f"- {fw}: {data['score']}% ({data['pass']} pass / {data['fail']} fail)"
        for fw, data in compliance_scores.items()
    )
    snippet = _findings_snippet(findings, n=40)
    # Pull out critical/high findings for spotlight
    critical_high = [f for f in findings if f.get("severity") in ("Critical", "High") and f.get("status") != "PASS"][:10]
    ch_lines = "\n".join(
        f"- [{f.get('severity')}] {f.get('service')} / {f.get('check_name')} (acct {f.get('account_id')}, {f.get('region')}): {f.get('details','')[:100]}"
        for f in critical_high
    )

    system = (
        "You are a senior cybersecurity consultant writing a board-level compliance report. "
        "Write in clear, professional Markdown. Be specific — name the actual failing checks, "
        "accounts, and services. Include a prioritised remediation table. "
        "Use real AWS service names and compliance control IDs."
    )
    user = f"""Write an executive compliance report for the following AWS security audit.

**Accounts audited:** {', '.join(account_ids)}
**Total findings:** {summary.get('total', 0)}
**Severity breakdown:** {json.dumps(stats['by_severity'])}
**Top failing checks:** {json.dumps(dict(stats['top_failing_checks']))}

**Compliance framework scores:**
{framework_lines}

**Critical & High findings (top 10):**
{ch_lines}

**All findings sample (60):**
{snippet}

Write a professional board-ready report with these sections:
1. Executive Summary (3-4 sentences, overall risk rating, top 3 issues)
2. Risk Overview (severity chart description, key themes)
3. Compliance Posture (per-framework score, what's failing, CIS/PCI/SOC2 gaps)
4. Critical & High Priority Issues (each with: what it is, business impact, fix action)
5. Remediation Roadmap (table: Priority | Finding | Effort | Owner | Timeline)
6. Recommended AWS CLI / CloudFormation fixes (3-5 copy-paste commands)
7. Conclusion

Target ~1000-1400 words. Be specific — cite real check names and account IDs."""

    return _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
