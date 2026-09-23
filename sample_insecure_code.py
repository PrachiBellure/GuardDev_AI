"""
Sample test script containing deliberate security flaws to validate the
AI Code Governance and Pre-Commit Security Guardrail.
"""

import os
import subprocess

# 1. Hallucinated / Unverified dependency test (MEASURE category)
# Note: Using try/except so the file does not crash if executed directly
try:
    import quick_ml_turbo_v9  # type: ignore
except ImportError:
    quick_ml_turbo_v9 = None


# 2. Exposed Credentials in Source (GOVERN category)
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
OPENAI_TOKEN = "sk-live1234567890abcdef1234567890abcdef"


# Mock database connection to eliminate Pylance / IDE linter warnings
class MockDatabaseCursor:
    def execute(self, query: str):
        pass


def run_dynamic_payload(user_input: str):
    """Dangerous dynamic execution (MAP category - CWE-95)"""
    eval(user_input)


def fetch_user_record(user_id: str):
    """Unparameterized SQL Injection pattern via f-string (MAP category - CWE-89)"""
    cursor = MockDatabaseCursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def run_system_command(command: str):
    """Dangerous subprocess shell execution (MAP category - CWE-78)"""
    subprocess.call(command, shell=True)