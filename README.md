# Enterprise AI Code Governance & Pre-Commit Guardrail

An automated security and compliance audit tool built to govern AI-generated code (tested with IBM Bob IDE). Maps code-level risks to the **NIST AI Risk Management Framework (AI RMF 1.0)**.

## Features
- **Secret Interception (GOVERN):** Detects exposed AWS credentials, OpenAI keys, and generic authorization tokens.
- **Static AST Analysis (MAP):** Flags dangerous dynamic execution (`eval`, `exec`), command injection (`shell=True`), and SQL injection patterns.
- **Supply-Chain Verification (MEASURE):** Identifies potential AI hallucinated imports and unpinned third-party dependencies.
- **Dual Reporting:** Outputs color-coded terminal alerts and machine-readable JSON logs for automated CI/CD pipelines.

## Usage

# Developer CLI Scan
python guardrail.py sample_insecure_code.py

# Machine-Readable JSON Export
python guardrail.py sample_insecure_code.py --format json > audit_report.json
