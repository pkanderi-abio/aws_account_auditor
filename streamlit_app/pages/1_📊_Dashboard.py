import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time
import streamlit as st
import plotly.graph_objects as go
from streamlit_app.lib import db, audit_runner

st.set_page_config(page_title="Dashboard · AWS Auditor", page_icon="📊", layout="wide")

st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
</style>
""", unsafe_allow_html=True)

if not db.is_logged_in():
    st.switch_page("app.py")

with st.sidebar:
    st.markdown("### 🛡️ AWS Auditor")
    st.markdown(f"**{st.session_state.get('user_email','')}**")
    st.divider()
    if st.button("Sign out", use_container_width=True):
        db.logout(); st.rerun()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0f172a,#1e293b);color:white;padding:2rem;border-radius:16px;margin-bottom:1rem">
  <h1 style="margin:0;display:flex;align-items:center;gap:12px">🛡️ AWS Audit Dashboard</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">Multi-account security, compliance &amp; cost analysis</p>
</div>""", unsafe_allow_html=True)

# ── Load jobs ─────────────────────────────────────────────────────────────────
jobs = db.list_audits()
config = db.get_config()

# ── Top action bar ────────────────────────────────────────────────────────────
col_left, col_right = st.columns([3, 1])
with col_right:
    has_running = any(j["status"] in ("pending", "running") for j in jobs)
    if not config:
        st.warning("No AWS config — go to ⚙️ Config first.")
        can_run = False
    else:
        can_run = not has_running

    if st.button("▶ Run New Audit", disabled=not can_run, type="primary", use_container_width=True):
        accounts = db.list_accounts()
        account_ids = [a["account_id"] for a in accounts]
        job = db.create_audit_job()
        audit_runner.start_audit(job["id"], db.current_user_id(), config, account_ids)
        st.success(f"Audit started (job {job['id'][:8]}…)")
        time.sleep(1)
        st.rerun()

    if has_running:
        st.info("Audit in progress…")
        time.sleep(5)
        st.rerun()

# ── Summary stats from latest completed job ───────────────────────────────────
latest = next((j for j in jobs if j["status"] == "completed"), None)
if latest:
    summary = db.get_summary(latest["id"])
    sev = summary.get("by_severity", {})
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Findings", summary["total"])
    c2.metric("🔴 Critical",    sev.get("Critical", 0))
    c3.metric("🟠 High",        sev.get("High", 0))
    c4.metric("🟡 Medium",      sev.get("Medium", 0))
    c5.metric("🟢 Low",         sev.get("Low", 0))

    # Charts row
    col_bar, col_svc = st.columns(2)
    with col_bar:
        st.subheader("Findings by Severity")
        sev_data = {k: sev.get(k, 0) for k in ["Critical", "High", "Medium", "Low"]}
        colors = {"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
        fig = go.Figure(go.Bar(
            x=list(sev_data.keys()),
            y=list(sev_data.values()),
            marker_color=[colors[k] for k in sev_data],
            text=list(sev_data.values()), textposition="outside",
        ))
        fig.update_layout(showlegend=False, margin=dict(t=0,b=0,l=0,r=0), height=250,
                          plot_bgcolor="white", paper_bgcolor="white")
        st.plotly_chart(fig, use_container_width=True)

    with col_svc:
        st.subheader("Top Services")
        svc = summary.get("by_service", {})
        if svc:
            top = dict(sorted(svc.items(), key=lambda x: x[1], reverse=True)[:8])
            fig2 = go.Figure(go.Bar(
                x=list(top.values()), y=list(top.keys()), orientation="h",
                marker_color="#3b82f6", text=list(top.values()), textposition="outside",
            ))
            fig2.update_layout(showlegend=False, margin=dict(t=0,b=0,l=0,r=0), height=250,
                               plot_bgcolor="white", paper_bgcolor="white")
            st.plotly_chart(fig2, use_container_width=True)

# ── Recent audits table ───────────────────────────────────────────────────────
st.subheader("Recent Audits")
STATUS_EMOJI = {"completed": "✅", "running": "🔄", "pending": "⏳", "failed": "❌"}

if not jobs:
    st.info("No audits yet — click **Run New Audit** to get started.")
else:
    for job in jobs:
        col_a, col_b, col_c, col_d, col_e = st.columns([2, 1, 1, 1, 1])
        with col_a:
            ts = job.get("created_at", "")[:19].replace("T", " ")
            st.markdown(f"**{ts}**")
        with col_b:
            emoji = STATUS_EMOJI.get(job["status"], "❓")
            st.markdown(f"{emoji} {job['status'].title()}")
        with col_c:
            accts = job.get("accounts_audited") or []
            st.markdown(f"{len(accts)} account{'s' if len(accts)!=1 else ''}")
        with col_d:
            total = job.get("total_findings", 0)
            st.markdown(f"{total} findings")
        with col_e:
            c1, c2 = st.columns(2)
            if job["status"] == "completed":
                if c1.button("View", key=f"view_{job['id']}", use_container_width=True):
                    st.session_state["selected_job"] = job["id"]
                    st.switch_page("pages/2_🔍_Findings.py")
            if job["status"] in ("completed", "failed"):
                if c2.button("🗑", key=f"del_{job['id']}", use_container_width=True):
                    db.delete_audit_job(job["id"])
                    st.rerun()
            if job.get("error_message"):
                st.caption(f"⚠ {job['error_message'][:80]}")
        st.divider()
