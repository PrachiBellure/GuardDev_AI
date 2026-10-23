import streamlit as st
import json
import os
import subprocess
import tempfile
import pandas as pd

st.set_page_config(
    page_title="GuardDev AI | Enterprise Code Governance",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Deep Slate & Electric Cyan / Indigo Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    code, pre, .stCode {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stDeployButton {
        display: none;
    }

    .stApp {
        background-color: #0b0f19;
        background-image: radial-gradient(circle at 15% 15%, rgba(14, 165, 233, 0.08) 0%, transparent 40%),
                          radial-gradient(circle at 85% 85%, rgba(99, 102, 241, 0.08) 0%, transparent 40%);
    }

    [data-testid="stSidebar"] {
        background-color: #080b13 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.06);
    }

    .hero-container {
        padding: 8px 0px 24px 0px;
    }
    
    .hero-badge {
        display: inline-block;
        padding: 4px 12px;
        background: rgba(14, 165, 233, 0.12);
        border: 1px solid rgba(14, 165, 233, 0.35);
        color: #38bdf8;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        margin-bottom: 12px;
    }

    .hero-title {
        font-size: 32px;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: -0.5px;
        margin: 0;
    }

    .hero-subtitle {
        color: #94a3b8;
        font-size: 14px;
        margin-top: 6px;
    }

    .metric-card {
        background: linear-gradient(135deg, rgba(23, 31, 51, 0.7) 0%, rgba(15, 23, 42, 0.7) 100%);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    
    .metric-card:hover {
        border-color: rgba(56, 189, 248, 0.4);
        transform: translateY(-2px);
    }

    .metric-label {
        font-size: 11px;
        font-weight: 700;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }

    .metric-value {
        font-size: 26px;
        font-weight: 800;
        color: #f1f5f9;
        margin-top: 4px;
    }

    .status-alert {
        color: #fb7185 !important;
        text-shadow: 0 0 16px rgba(251, 113, 133, 0.3);
    }
    
    .status-ok {
        color: #34d399 !important;
        text-shadow: 0 0 16px rgba(52, 211, 153, 0.3);
    }

    div.stButton > button {
        background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        font-size: 14px !important;
        letter-spacing: 0.5px !important;
        padding: 12px 24px !important;
        box-shadow: 0 4px 18px rgba(14, 165, 233, 0.35) !important;
        transition: all 0.2s ease-in-out !important;
    }

    div.stButton > button:hover {
        background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%) !important;
        box-shadow: 0 6px 24px rgba(14, 165, 233, 0.55) !important;
        transform: translateY(-1px) !important;
    }
    
    textarea {
        background-color: #0f172a !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        color: #e2e8f0 !important;
    }
</style>
""", unsafe_allow_html=True)

# Hero Header
st.markdown("""
<div class="hero-container">
    <div class="hero-badge">⚡ Real-time AST Engine Active</div>
    <h1 class="hero-title">GuardDev Code Governance Platform</h1>
    <p class="hero-subtitle">Automated static AST policy enforcement, secret detection, and NIST AI RMF compliance verification.</p>
</div>
""", unsafe_allow_html=True)

# Sidebar Configuration
with st.sidebar:
    st.markdown("### Source Input")
    input_mode = st.radio(
        "Source Selection",
        ["Load Default Test Suite", "Paste Code Snippet", "Upload File (.py)"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    st.markdown("### Active Security Policies")
    st.markdown("""
    * **CWE-798** Credential Leaks
    * **CWE-89** SQL Injections
    * **CWE-78 / 95** Dynamic Injections
    * **CWE-1104** Hallucinated Deps
    """)
    st.markdown("---")
    st.caption("Engine Target: NIST AI RMF 1.0 (GOVERN / MAP)")

# Load Code Source
source_code = ""

if input_mode == "Load Default Test Suite":
    if os.path.exists("sample_insecure_code.py"):
        with open("sample_insecure_code.py", "r", encoding="utf-8") as f:
            source_code = f.read()
    else:
        st.warning("`sample_insecure_code.py` not found in root.")
elif input_mode == "Upload File (.py)":
    uploaded = st.file_uploader("Upload Python script", type=["py"], label_visibility="collapsed")
    if uploaded:
        source_code = uploaded.read().decode("utf-8")
else:
    source_code = st.text_area(
        "Source Input Buffer",
        height=200,
        placeholder="# Paste target Python code here...",
        label_visibility="collapsed"
    )

# Execution Button
run_audit = st.button("RUN SECURITY AUDIT", use_container_width=True)

# Run Engine Workflow
if run_audit and source_code.strip():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as temp_file:
        temp_file.write(source_code)
        temp_path = temp_file.name

    try:
        proc = subprocess.run(
            ["python", "guardrail.py", temp_path],
            capture_output=True,
            text=True
        )
        cli_trace = proc.stdout + proc.stderr

        # Parse Audit JSON (handles array and dictionary structures)
        findings = []
        raw_json_data = None
        if os.path.exists("audit_report.json"):
            with open("audit_report.json", "r", encoding="utf-8") as rf:
                try:
                    raw_json_data = json.load(rf)
                    if isinstance(raw_json_data, list):
                        findings = raw_json_data
                    elif isinstance(raw_json_data, dict):
                        findings = (
                            raw_json_data.get("findings")
                            or raw_json_data.get("violations")
                            or raw_json_data.get("audit_results")
                            or []
                        )
                except Exception:
                    findings = []

        # Metric Calculations with CLI Fallback
        if not findings and ("[CRITICAL]" in cli_trace or "[HIGH]" in cli_trace):
            critical_count = cli_trace.count("[CRITICAL]")
            total_findings = cli_trace.count("[CRITICAL]") + cli_trace.count("[HIGH]") + cli_trace.count("[MEDIUM]")
        else:
            total_findings = len(findings)
            critical_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")

        status_label = "POLICY BLOCKED" if total_findings > 0 else "PASSED"
        status_style = "status-alert" if total_findings > 0 else "status-ok"

        # Telemetry Display
        st.markdown("<br>", unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        
        with m1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Pipeline Gate</div>
                <div class="metric-value {status_style}">{status_label}</div>
            </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Detected Flaws</div>
                <div class="metric-value">{total_findings}</div>
            </div>
            """, unsafe_allow_html=True)
        with m3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Critical Severity</div>
                <div class="metric-value status-alert">{critical_count}</div>
            </div>
            """, unsafe_allow_html=True)
        with m4:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-label">Standard Alignment</div>
                <div class="metric-value" style="color: #38bdf8;">NIST 1.0</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Workstation Grid
        col_main, col_logs = st.columns([1.3, 0.7])

        with col_main:
            st.markdown("#### Violation Breakdown")
            if findings:
                table_data = []
                for item in findings:
                    table_data.append({
                        "Severity": str(item.get("severity", "HIGH")).upper(),
                        "CWE": item.get("cwe", "CWE-Unknown"),
                        "Line": item.get("line", "N/A"),
                        "Category": item.get("category", "General Vulnerability"),
                        "Description": item.get("description", "Vulnerability detected."),
                        "Code Snippet": item.get("snippet", "")
                    })
                df = pd.DataFrame(table_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
            elif total_findings > 0:
                st.warning("Violations caught by CLI engine stream. View runtime log on the right.")
            else:
                st.success("Clean Build: 0 policy violations identified.")

            st.markdown("#### Inspected Source Buffer")
            st.code(source_code, language="python", line_numbers=True)

        with col_logs:
            st.markdown("#### CLI Runtime Stream")
            st.code(cli_trace if cli_trace else "Process completed with exit code 0.", language="bash")

            if raw_json_data:
                st.download_button(
                    label="Download Audit Report (JSON)",
                    data=json.dumps(raw_json_data, indent=2),
                    file_name="audit_report.json",
                    mime="application/json",
                    use_container_width=True
                )

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)