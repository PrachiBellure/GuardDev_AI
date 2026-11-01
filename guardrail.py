import ast
import json
import math
import os
import re
import sys

# Comprehensive signature patterns for arbitrary secrets
SECRET_KEYWORD_REGEX = re.compile(
    r'(?i)(secret|token|api_?key|auth|password|passwd|pwd|access_?key|private_?key|client_?secret|conn_?str|database_?url)'
)

KNOWN_SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                                  # AWS Access Key ID
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),                              # OpenAI / Standard service keys
    re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),                   # GitHub Tokens
    re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),                    # Slack Tokens
    re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),         # JWT Tokens
    re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), # Private Keys
]

# Baseline standard dependencies (flags unverified/hallucinated external imports)
STANDARD_OR_APPROVED_PKGS = {
    "os", "sys", "re", "math", "json", "ast", "tempfile", "subprocess", "datetime",
    "collections", "itertools", "pathlib", "typing", "sqlite3", "pandas", "streamlit",
    "requests", "numpy", "dotenv", "pydantic", "fastapi", "flask"
}

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect high-randomness tokens."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

class SecurityScanner(ast.NodeVisitor):
    def __init__(self, filename="<input>"):
        self.filename = filename
        self.violations = []

    def visit_Import(self, node):
        """CWE-1104: Scan standard imports for untracked or hallucinated packages."""
        for alias in node.names:
            pkg = alias.name.split('.')[0]
            if pkg not in STANDARD_OR_APPROVED_PKGS:
                self.violations.append({
                    "category": "Unverified Dependency",
                    "cwe": "CWE-1104",
                    "nist_rmf": "MAP",
                    "severity": "MEDIUM",
                    "file": self.filename,
                    "line": node.lineno,
                    "description": f"Unverified or potential hallucinated dependency '{pkg}'.",
                    "snippet": f"import {alias.name}"
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """CWE-1104: Scan from-imports for untracked or hallucinated packages."""
        if node.module:
            pkg = node.module.split('.')[0]
            if pkg not in STANDARD_OR_APPROVED_PKGS:
                self.violations.append({
                    "category": "Unverified Dependency",
                    "cwe": "CWE-1104",
                    "nist_rmf": "MAP",
                    "severity": "MEDIUM",
                    "file": self.filename,
                    "line": node.lineno,
                    "description": f"Unverified or potential hallucinated dependency '{pkg}'.",
                    "snippet": f"from {node.module} import ..."
                })
        self.generic_visit(node)

    def visit_Assign(self, node):
        """CWE-798: Arbitrary exposed credential detection using heuristics, patterns & entropy."""
        target_names = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id)
            elif isinstance(target, ast.Attribute):
                target_names.append(target.attr)

        string_val = None
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            string_val = node.value.value
        elif hasattr(ast, "Str") and isinstance(node.value, ast.Str):
            string_val = node.value.s

        if string_val:
            val_clean = string_val.strip()
            if len(val_clean) > 6 and not val_clean.startswith("${") and not val_clean.startswith("env:"):
                matches_pattern = any(pattern.search(val_clean) for pattern in KNOWN_SECRET_PATTERNS)
                matches_var_name = any(SECRET_KEYWORD_REGEX.search(name) for name in target_names)
                entropy = calculate_shannon_entropy(val_clean)
                is_high_entropy = len(val_clean) >= 16 and entropy >= 3.2

                if matches_pattern or (matches_var_name and len(val_clean) >= 8) or (matches_var_name and is_high_entropy):
                    masked = val_clean[:4] + "*" * (len(val_clean) - 6) + val_clean[-2:] if len(val_clean) > 8 else "********"
                    target_str = ", ".join(target_names) if target_names else "unnamed_variable"
                    self.violations.append({
                        "category": "Exposed Hardcoded Credential",
                        "cwe": "CWE-798",
                        "nist_rmf": "GOVERN",
                        "severity": "CRITICAL",
                        "file": self.filename,
                        "line": node.lineno,
                        "description": f"Exposed credential or secret key assigned to '{target_str}'.",
                        "snippet": f"{target_str} = \"{masked}\""
                    })

        self.generic_visit(node)

    def visit_Call(self, node):
        """CWE-78 / CWE-95 / CWE-89: Detection of dangerous runtime commands and injections."""
        # 1. Check for eval(), exec()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec"):
                self.violations.append({
                    "category": "Dynamic Code Execution",
                    "cwe": "CWE-95",
                    "nist_rmf": "MAP",
                    "severity": "CRITICAL",
                    "file": self.filename,
                    "line": node.lineno,
                    "description": f"Direct invocation of '{func_name}()' allowing arbitrary execution.",
                    "snippet": f"{func_name}(...)"
                })

        # 2. Check for os.system(...)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                self.violations.append({
                    "category": "OS Command Injection",
                    "cwe": "CWE-78",
                    "nist_rmf": "MAP",
                    "severity": "CRITICAL",
                    "file": self.filename,
                    "line": node.lineno,
                    "description": "Unsanitized system shell invocation via 'os.system()'.",
                    "snippet": "os.system(...)"
                })

            # 3. Check for subprocess.call/Popen/run(..., shell=True)
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.violations.append({
                            "category": "Subprocess Shell Execution",
                            "cwe": "CWE-78",
                            "nist_rmf": "MAP",
                            "severity": "CRITICAL",
                            "file": self.filename,
                            "line": node.lineno,
                            "description": "Subprocess invoked with shell=True, enabling shell injection.",
                            "snippet": f"subprocess.{node.func.attr}(..., shell=True)"
                        })

            # 4. Check for cursor.execute() unparameterized query formatting
            elif node.func.attr == "execute":
                if node.args:
                    arg = node.args[0]
                    # Direct f-string or % or .format() in execute
                    if isinstance(arg, ast.JoinedStr) or isinstance(arg, ast.BinOp):
                        self.violations.append({
                            "category": "SQL Injection",
                            "cwe": "CWE-89",
                            "nist_rmf": "MAP",
                            "severity": "CRITICAL",
                            "file": self.filename,
                            "line": node.lineno,
                            "description": "Direct string interpolation detected in database query execute call.",
                            "snippet": "cursor.execute(f\"...\")"
                        })

        self.generic_visit(node)


def run_scan(target_path: str):
    """Parses Python file, traverses AST, outputs CLI report, and saves JSON log."""
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            code_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    try:
        tree = ast.parse(code_content, filename=target_path)
    except SyntaxError as e:
        print(f"[ERROR] SyntaxError while parsing AST: {e}")
        sys.exit(1)

    scanner = SecurityScanner(filename=target_path)
    scanner.visit(tree)
    violations = scanner.violations

    # Print CLI stream report
    print("==================================================")
    print("  NIST AI RMF 1.0 SECURE CODE GOVERNANCE ENGINE   ")
    print(f"  Scanned Files: 1  |  Total Flaws: {len(violations)}")
    print("==================================================\n")

    for v in violations:
        sev = v["severity"]
        cwe = v["cwe"]
        nist = v["nist_rmf"]
        color_code = "\033[91m" if sev == "CRITICAL" else "\033[93m"
        reset_code = "\033[0m"

        print(f"{color_code}[{sev}] {nist} · {v['category']} ({cwe}){reset_code}")
        print(f"  Location : {v['file']}:{v['line']}")
        print(f"  Detail   : {v['description']}")
        print(f"  Code     : {v['snippet']}\n")

    # Save output to audit_report.json as a direct list of objects
    report_file = "audit_report.json"
    with open(report_file, "w", encoding="utf-8") as rf:
        json.dump(violations, rf, indent=2)

    return len(violations)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = "sample_insecure_code.py"
    else:
        target = sys.argv[1]

    flaws_count = run_scan(target)
    sys.exit(1 if flaws_count > 0 else 0)