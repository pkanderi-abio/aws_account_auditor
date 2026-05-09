"""
Entry point for Streamlit Community Cloud.
Run locally:  streamlit run streamlit_app/app.py
"""
import sys, os
_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
_LOGO = os.path.normpath(os.path.join(_LIB, "..", "..", "auditor", "assets", "logo.png"))
import streamlit as st
import db

st.set_page_config(
    page_title="AWS Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  [data-testid="stSidebar"] { background: #0f172a; }
  [data-testid="stSidebar"] * { color: #e2e8f0 !important; }
  [data-testid="stSidebarNav"] a { color: #e2e8f0 !important; }
  .metric-card { background: white; border-radius: 12px; padding: 1rem; border: 1px solid #e5e7eb; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .sev-critical { color: #dc2626; font-weight: 700; }
  .sev-high     { color: #f97316; font-weight: 700; }
  .sev-medium   { color: #eab308; font-weight: 700; }
  .sev-low      { color: #22c55e; font-weight: 700; }
  .tag { display:inline-block; padding:2px 8px; border-radius:9999px; font-size:0.7rem; font-weight:600; margin:2px; }
  .finding-card { background:white; border:1px solid #e5e7eb; border-radius:12px; padding:1rem; margin:0.5rem 0; }
</style>
""", unsafe_allow_html=True)

# ── Handle OAuth callback (?code= query param) ────────────────────────────────
params = st.query_params
if "code" in params and not db.is_logged_in():
    with st.spinner("Completing sign-in…"):
        ok, err = db.exchange_oauth_code(params["code"])
    if ok:
        st.query_params.clear()
        st.rerun()
    else:
        st.error(f"OAuth sign-in failed: {err}")

# ── Already logged in → go to dashboard ───────────────────────────────────────
db.restore_session()
if db.is_logged_in():
    with st.sidebar:
        if os.path.exists(_LOGO):
            st.image(_LOGO, use_container_width=True)
        else:
            st.markdown("### 🛡️ AWS Auditor")
        st.markdown(f"**{st.session_state.get('user_email', '')}**")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            db.logout()
            st.rerun()
    st.switch_page("pages/1_📊_Dashboard.py")

# ── App URL for OAuth redirect ────────────────────────────────────────────────
try:
    APP_URL = str(st.secrets.get("app_url", "https://awsauditor.streamlit.app"))
except Exception:
    APP_URL = "https://awsauditor.streamlit.app"

# ── Login page ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Hide default Streamlit header/footer on login page */
#MainMenu, footer, header { visibility: hidden; }

/* Full-width login layout */
.block-container { padding: 0 !important; max-width: 100% !important; }

.login-left {
  background: linear-gradient(160deg, #0f172a 0%, #1e3a5f 60%, #0f172a 100%);
  min-height: 100vh;
  padding: 3rem 2.5rem;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  color: white;
}
.login-right {
  background: #ffffff;
  min-height: 100vh;
  padding: 3rem 2.5rem;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.feature-item {
  display: flex; align-items: flex-start; gap: 12px;
  margin-bottom: 1.1rem; font-size: 0.95rem; color: #cbd5e1;
}
.feature-icon {
  width: 32px; height: 32px; border-radius: 8px;
  background: rgba(255,255,255,0.1);
  display: flex; align-items: center; justify-content: center;
  font-size: 1rem; flex-shrink: 0; margin-top: 1px;
}
.oauth-btn {
  display: flex; align-items: center; justify-content: center; gap: 10px;
  width: 100%; padding: 11px 16px; border-radius: 10px; font-size: 0.95rem;
  font-weight: 600; cursor: pointer; text-decoration: none !important;
  transition: all 0.18s ease; border: 1.5px solid #e5e7eb;
  color: #1e293b !important; background: #fff; margin-bottom: 10px;
}
.oauth-btn:hover { border-color: #94a3b8; background: #f8fafc; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,.08); }
.oauth-btn img { width: 20px; height: 20px; }
.divider-text {
  display: flex; align-items: center; gap: 12px;
  color: #94a3b8; font-size: 0.85rem; margin: 18px 0;
}
.divider-text::before, .divider-text::after {
  content: ""; flex: 1; height: 1px; background: #e5e7eb;
}
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 99px;
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em;
  background: rgba(59,130,246,0.15); color: #93c5fd; margin-right: 6px;
}
</style>
""", unsafe_allow_html=True)

left, right = st.columns([1, 1], gap="small")

# ── LEFT PANEL ─────────────────────────────────────────────────────────────────
with left:
    st.markdown('<div class="login-left">', unsafe_allow_html=True)

    if os.path.exists(_LOGO):
        logo_col, _ = st.columns([1, 2])
        with logo_col:
            st.image(_LOGO, use_container_width=True)
    else:
        st.markdown("## 🛡️ AWS Security Auditor")

    st.markdown("""
<div style="margin:1.8rem 0 0.5rem">
  <span class="badge">MULTI-ACCOUNT</span>
  <span class="badge">AI-POWERED</span>
  <span class="badge">CIS · PCI · SOC2</span>
</div>
<h2 style="color:white;font-size:1.8rem;font-weight:800;margin:0.5rem 0 0.3rem;line-height:1.2">
  Unified AWS Security<br>Audit Platform
</h2>
<p style="color:#94a3b8;font-size:0.95rem;margin-bottom:2rem">
  Continuous compliance, AI-driven insights, and<br>
  actionable remediation across all your AWS accounts.
</p>
""", unsafe_allow_html=True)

    features = [
        ("🔍", "Multi-account IAM, network & cost audit"),
        ("🤖", "AI analysis with CLI & CloudFormation fixes"),
        ("📋", "CIS, PCI-DSS, SOC 2, HIPAA, NIST scoring"),
        ("⚡", "One-click audit with real-time findings"),
        ("🔒", "Role-based cross-account access — no keys stored"),
    ]
    for icon, text in features:
        st.markdown(f"""
<div class="feature-item">
  <div class="feature-icon">{icon}</div>
  <span>{text}</span>
</div>""", unsafe_allow_html=True)

    st.markdown("""
<div style="margin-top:auto;padding-top:2rem;color:#475569;font-size:0.8rem">
  © 2025 H&amp;H IT Solutions · <a href="mailto:info@hhitsolutions.com" style="color:#64748b">info@hhitsolutions.com</a>
</div>
""", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── RIGHT PANEL ────────────────────────────────────────────────────────────────
with right:
    st.markdown('<div class="login-right">', unsafe_allow_html=True)

    # Centered inner container
    _, center, _ = st.columns([1, 6, 1])
    with center:
        st.markdown("""
<h2 style="font-size:1.7rem;font-weight:800;color:#0f172a;margin-bottom:0.3rem">Welcome back</h2>
<p style="color:#64748b;margin-bottom:1.5rem">Sign in to your account or create a new one</p>
""", unsafe_allow_html=True)

        # ── OAuth buttons ──────────────────────────────────────────────────────
        PROVIDERS = [
            ("google",    "https://www.google.com/favicon.ico",    "Continue with Google"),
            ("github",    "https://github.com/favicon.ico",         "Continue with GitHub"),
            ("azure",     "https://microsoft.com/favicon.ico",      "Continue with Microsoft"),
        ]
        for provider, favicon, label in PROVIDERS:
            url, err = db.get_oauth_url(provider, APP_URL)
            if url:
                st.markdown(
                    f'<a href="{url}" class="oauth-btn" target="_self">'
                    f'<img src="{favicon}" onerror="this.style.display=\'none\'">'
                    f'{label}</a>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="oauth-btn" style="opacity:.4;cursor:not-allowed">'
                    f'{label} <small style="font-weight:400">(not configured)</small></div>',
                    unsafe_allow_html=True,
                )

        st.markdown('<div class="divider-text">or continue with email</div>',
                    unsafe_allow_html=True)

        # ── Email / password tabs ──────────────────────────────────────────────
        tab_in, tab_up = st.tabs(["Sign in", "Create account"])

        with tab_in:
            with st.form("login_form"):
                email    = st.text_input("Email", placeholder="you@example.com", label_visibility="collapsed" if False else "visible")
                password = st.text_input("Password", type="password", placeholder="••••••••")
                submitted = st.form_submit_button("Sign in →", use_container_width=True, type="primary")
            if submitted:
                ok, err = db.login(email, password)
                if ok:
                    st.rerun()
                else:
                    st.error(err)

        with tab_up:
            with st.form("signup_form"):
                new_email  = st.text_input("Email", placeholder="you@example.com", key="su_email")
                new_pw     = st.text_input("Password", type="password", placeholder="Min 8 characters", key="su_pw")
                new_pw2    = st.text_input("Confirm password", type="password", placeholder="Re-enter password", key="su_pw2")
                register   = st.form_submit_button("Create account →", use_container_width=True, type="primary")
            if register:
                if new_pw != new_pw2:
                    st.error("Passwords don't match.")
                elif len(new_pw) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    ok, status = db.signup(new_email, new_pw)
                    if not ok:
                        st.error(status)
                    elif status == "confirm":
                        st.success("Account created! Check your email to confirm, then sign in.")
                    else:
                        st.rerun()

        st.markdown("""
<p style="text-align:center;color:#94a3b8;font-size:0.78rem;margin-top:1.5rem">
  By signing in you agree to our Terms of Service.<br>
  Your AWS credentials never leave your account.
</p>
""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
