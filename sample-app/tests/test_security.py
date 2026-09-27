from pathlib import Path
from app import app

def test_profile_requires_authorization():
    # Expected to FAIL before remediation.
    r = app.test_client().get("/profile/2")
    assert r.status_code == 403

def test_sql_injection_is_not_exploitable():
    # Expected to FAIL before remediation.
    payload = "' OR '1'='1"
    r = app.test_client().get("/search", query_string={"q": payload})
    assert r.status_code == 200
    assert r.get_json() == []

def test_xss_is_escaped():
    # Expected to FAIL before remediation.
    payload = "<script>alert('x')</script>"
    r = app.test_client().get("/echo", query_string={"message": payload})
    assert r.status_code == 200
    assert b"&lt;script&gt;" in r.data
    assert b"<script>alert('x')</script>" not in r.data

def test_exception_details_are_not_exposed():
    # Expected to FAIL before remediation.
    r = app.test_client().get("/divide?a=10&b=0")
    assert r.status_code == 500
    assert (r.get_json() or {}).get("error") == "Internal server error"

def test_secret_is_not_hardcoded():
    # Expected to FAIL before remediation.
    source = Path("config.py").read_text(encoding="utf-8")
    assert "SentryHeal-DEMO-HARDCODED-SECRET-2026" not in source
