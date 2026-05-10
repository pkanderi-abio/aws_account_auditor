# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Setup (CLI auditor only)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r auditor/requirements.txt
```

### Run the auditor (CLI — local reports)
```bash
python3 -m auditor.main
```

### Launch the SaaS Streamlit app (primary)
```bash
pip install -r requirements.txt
streamlit run streamlit_app/app.py
```

### Run tests
```bash
python3 -m pytest auditor/tests/
```

## Architecture

Two modes exist side-by-side:

### 1. SaaS app — `streamlit_app/` (primary, deployed to Streamlit Cloud)
Multi-tenant Streamlit application with Supabase backend. Users sign in, configure their AWS role chain via the UI, and trigger audits that run in background threads.

**Entry point:** `streamlit_app/app.py`  
**Dependencies:** `requirements.txt` (root)  
**Deployed at:** `awsauditor.streamlit.app`

#### Page layout (`streamlit_app/pages/`)
| File | Purpose |
|---|---|
| `1_📊_Dashboard.py` | Audit list, trigger new audit, summary charts |
| `2_🔍_Findings.py` | Filter/browse findings, AI remediation per finding |
| `3_📋_Compliance.py` | Compliance scorecards (CIS, PCI, SOC2, HIPAA, NIST) |
| `4_🤖_AI.py` | AI analysis, chat, executive report generation |
| `5_⚙️_Config.py` | AWS role chain + account configuration (saved to Supabase) |
| `6_🛠️_Settings.py` | AI provider status, data management, environment diagnostics |

#### Lib layer (`streamlit_app/lib/`)
- `db.py` — all Supabase reads/writes (auth, config, accounts, audit jobs, findings, AI analyses). Uses service role key server-side. Cookie-based session persistence via `streamlit-cookies-controller`.
- `audit_runner.py` — runs `auditor/` modules in a daemon thread, updates Supabase as it progresses.
- `ai_client.py` — Groq (cloud, default) or Ollama (local) LLM calls for analysis, remediation, and report generation.

#### Import pattern (all pages must use this — Python 3.14 compatibility)
```python
_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import db, ai_client   # direct imports, NOT from streamlit_app.lib import ...
```

#### Secrets (`.streamlit/secrets.toml`, never committed)
```toml
[supabase]
url = "https://xxx.supabase.co"
anon_key = "eyJ..."
service_role_key = "eyJ..."

GROQ_API_KEY = "gsk_..."
app_url = "https://awsauditor.streamlit.app"
```

### 2. CLI auditor — `auditor/` (local use, produces JSON/CSV/HTML reports)
Standalone tool. Auth chain: local SSO profile → AuditDeployer role → AuditRole per account.

**Config:** `auditor/config.yaml` (gitignored — never commit)  
**Reports:** `auditor/reports/` (gitignored — may contain real account data)

#### Execution flow
`main.py` → loads `config.yaml` → resolves account list → assumes AuditRole per account → `orchestrator.run_all_audits()` → saves to `auditor/reports/`

The orchestrator (`auditor/modules/orchestrator.py`) runs all modules concurrently via `ThreadPoolExecutor`. Each module receives `(session, account_id, regions)` and returns a list of findings.

#### Audit modules (`auditor/modules/`)
| Module | Key file |
|---|---|
| IAM best practices | `iam_audit.py` |
| Network exposure | `network_assessment.py` |
| Cost optimization | `cost_optimization.py` |
| Public exposure (S3, AMIs, etc.) | `exposure_audit.py` |
| CloudTrail & GuardDuty | `cloudtrail_guardduty.py` |
| Security Hub findings | `security_best_practices.py` |
| Cyber posture | `aws_cyber_audit.py` |

#### Finding schema
All modules must return findings conforming to `auditor/modules/constants.py:STANDARD_FINDING`:
```
AccountId, Region, Service, Check, Status (PASS/WARNING/FAIL/ERROR/SKIPPED),
Severity (Low/Medium/High/Critical), FindingType, Details, Recommendation,
Timestamp (ISO), Compliance (dict, e.g. {"CIS": "3.1"})
```

### Infrastructure files (root level)
- `auditrole_stackset_template.yaml` — CloudFormation StackSet template; creates `AuditRole` in every target account.
- `cloudtrail_stackset_template.yaml` — CloudFormation StackSet template; enables CloudTrail across all accounts with CIS alarms.
- `deploy_audit_deployer.yaml` — CloudFormation template for `AuditDeployer` role in the management account.
- `delete_role.sh`, `delete_stackset_instances.sh`, `force_delete_auditrole_stacks.py`, `delete_createauditrole_stacks.py` — cleanup utilities.
- `auto-deploy.json` — StackSet auto-deployment config.

### Dead code / unused
- `backend/` — FastAPI + Celery backend scaffolded during SaaS conversion. Replaced by Streamlit + Supabase direct. Not deployed.
- `frontend/` — Next.js frontend scaffolded during SaaS conversion. Not deployed; SaaS UI is in `streamlit_app/`.
- `auditor/dashboard.py` — old local-only Streamlit dashboard. Superseded by `streamlit_app/`.
