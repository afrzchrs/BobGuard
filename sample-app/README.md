# SentryHeal Test App
Deliberately vulnerable Flask + SQLite app for LOCAL defensive testing of SentryHeal.

Vulnerabilities:
1. A01:2025 Broken Access Control (IDOR-style profile access)
2. A02:2025 Security Misconfiguration (hardcoded SECRET_KEY)
3. A05:2025 Injection (SQL injection)
4. A05:2025 Injection (reflected XSS)
5. A10:2025 Mishandling of Exceptional Conditions (raw exception leakage)

Run locally:
python -m venv .venv
pip install -r requirements.txt
python seed_db.py
python app.py

Then:
http://127.0.0.1:5000/

Tests:
pytest -q

Important: tests/test_security.py are expected to FAIL before remediation and PASS after a correct SentryHeal patch. This gives a clear Audit -> Patch -> Test -> Re-scan -> Verify demo.
