# Security Test Cases

1. A01:2025 Broken Access Control -> `/profile/<user_id>`
2. A02:2025 Security Misconfiguration -> hardcoded `SECRET_KEY`
3. A05:2025 Injection -> `/search`
4. A05:2025 Injection -> `templates/search.html`
5. A10:2025 Mishandling of Exceptional Conditions -> `/divide`

The security tests intentionally fail before remediation and should pass after correct remediation.
