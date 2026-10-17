import streamlit as st
import json
import os
import subprocess
import tempfile

st.set_page_config(
    page_title="GuardDev | Security & Privacy Audit Console",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ Enterprise Code Security & Privacy Guardrail")
st.caption("Automated Static Analysis Engine (AST & Pattern Matching) • NIST AI RMF 1.0 Aligned")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("⚙️ Audit Configuration")
    input_mode = st.radio("Input Source", ["Paste Code Snippet", "Upload .py File", "Load Default Test Suite"])
    st.markdown("---")
    st.markdown("**Compliance Checks:**")
    st.markdown("- CWE-798: Hardcoded Credentials")
    st.markdown("- CWE-89: SQL Injection")
    st.markdown("- CWE-78 / 95: Dynamic Execution")
    st.markdown("- CWE-1104: Unverified Dependencies")

# Input Handling
code_to_scan = ""

if input_mode == "Load Default Test Suite":
    if os.path.exists("sample_insecure_code.py"):
        with open("sample_insecure_code.py", "r", encoding="utf-8") as f:
            code_to_scan = f.read()
    else:
        st.warning("sample_insecure_code.py not found.")
elif input_mode == "Upload .py File":
    uploaded_file = st.file_uploader("Upload Python file", type=["py"])
    if uploaded_file is not None:
        code_to_scan = uploaded_file.read().decode("utf-8")
else:
    code_to_scan = st.text_area("Source Code to Inspect:", height=200, placeholder="Paste Python code here...")

# Scan Button
if st.button("🚀 Run Security Audit", use_container_width=True) and code_to_scan.strip():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as temp_file:
        temp_file.write(code_to_scan)
        temp_file_path = temp_file.name

    try:
        process = subprocess.run(
            ["python", "guardrail.py", temp_file_path],
            capture_output=True,
            text=True
        )
        cli_output = process.stdout + process.stderr

        report_data = None
        if os.path.exists("audit_report.json"):
            with open("audit_report.json", "r", encoding="utf-8") as rf:
                try:
                    report_data = json.load(rf)
                except Exception:
                    report_data = None

        col_findings, col_terminal = st.columns([1.2, 0.8])

        with col_findings:
            st.subheader("🔍 Policy Violations Detected")
            if report_data and report_data.get("findings"):
                for issue in report_data["findings"]:
                    cwe = issue.get("cwe", "CWE-Unknown")
                    sev = issue.get("severity", "HIGH").upper()
                    line = issue.get("line", "N/A")
                    desc = issue.get("description", "Security vulnerability detected.")
                    st.error(f"[{sev}] {cwe} (Line {line}): {desc}")
            elif report_data and not report_data.get("findings"):
                st.success("✅ Clean Build: No security violations found.")
            else:
                st.info("Scan completed. See output log.")

        with col_terminal:
            st.subheader("🖥️ Execution Log")
            st.code(cli_output if cli_output else "Scanner finished cleanly.", language="bash")
            if report_data:
                st.download_button(
                    label="📥 Download audit_report.json",
                    data=json.dumps(report_data, indent=2),
                    file_name="audit_report.json",
                    mime="application/json"
                )
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)