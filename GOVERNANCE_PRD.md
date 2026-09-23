# Product Requirements Document (PRD)
## Enterprise AI Code Governance & Pre-Commit Policy Engine (GuardDev)

**Document Version:** 1.0.0  
**Target Audience:** Engineering Leads, Enterprise SecOps, AI Governance Officers  
**Regulatory Framework:** NIST AI Risk Management Framework (AI RMF 1.0)

---

### 1. Executive Summary & Problem Definition
Generative AI development tools (such as IBM Bob, GitHub Copilot) accelerate software velocity but introduce three critical enterprise risks:
1. **Exfiltration of High-Value Secrets:** Accidental inclusion of hardcoded cloud keys, JWTs, and database credentials into code files and AI context windows.
2. **AI Hallucinations & Supply-Chain Attacks:** LLMs generating non-existent package dependencies, opening attack vectors for package typosquatting and dependency confusion.
3. **Insecure Code Generation:** Silent insertion of dynamic code execution flaws (CWE-78, CWE-89, CWE-95) bypassing manual code reviews.

**GuardDev** enforces automated, zero-overhead pre-commit policy gates that evaluate code structure before commits reach remote repositories.

---

### 2. NIST AI RMF 1.0 Policy Mapping

| NIST Function | Subcategory | Risk Identified | Automated Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **GOVERN** | GV-1.1, GV-4.1 | Credential exposure & data leaks | Regex entropy scanners intercept AWS, OpenAI, and high-entropy private keys; immediate commit termination on match. |
| **MAP** | MP-2.3, MP-3.1 | Dangerous logic injection | AST (Abstract Syntax Tree) traversal catches `eval()`, `exec()`, `shell=True`, and unparameterized SQL strings. |
| **MEASURE** | MS-2.1, MS-2.5 | Dependency hallucinations | Cross-references third-party imports against standard libraries and untrusted package signatures. |
| **MANAGE** | MN-1.2, MN-2.2 | Insecure deployments | Policy Gate: Halts deployment pipeline on `CRITICAL` or `HIGH` findings; requires Human-in-the-Loop (HITL) override. |

---

### 3. Product KPIs & Acceptance Criteria
- **Credential Interception Rate:** 100% detection on standard enterprise API key syntaxes (AWS, OpenAI, Private Keys).
- **Audit Latency:** < 500 ms per file scan to eliminate developer workflow friction.
- **Reporting:** Dual-format delivery—interactive CLI terminal reports for developers, and machine-readable JSON artifacts for enterprise SIEM ingestion.