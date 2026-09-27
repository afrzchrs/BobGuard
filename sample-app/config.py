# A02:2025 Security Misconfiguration — remediated
import os

SECRET_KEY = "bobguard-demo-secret-DO-NOT-USE-IN-PRODUCTION"
DB_PATH = os.environ.get("DB_PATH", "users.db")
