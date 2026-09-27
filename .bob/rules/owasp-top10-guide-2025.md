# Universal OWASP Top 10:2025 Security Audit Rules

This document establishes the baseline evaluation criteria for application security findings across multiple programming languages and frameworks (Node.js, Python, Java, Go, PHP, C#, and common web stacks). Use these specifications to identify evidence-based security weaknesses, map them to OWASP Top 10:2025, and propose context-aware remediation.

> **Scope note:** OWASP Top 10:2025 is an awareness/risk classification, not a complete automated security-testing standard. The agent MUST NOT claim comprehensive or 100% automated coverage. For verifiable controls, prefer concrete evidence and, where appropriate, map findings to CWE and/or OWASP ASVS controls.

---

## A01:2025 - Broken Access Control

- **Detection Criteria:**
  - Protected endpoints or sensitive operations that lack server-side authentication/authorization enforcement.
  - IDOR/BOLA: user-controlled object identifiers are used without verifying ownership or permitted scope.
  - Privilege escalation through client-controlled role/permission fields.
  - Missing function-level authorization or tenant isolation.
  - Access-control checks performed only in client-side code.
  - Potential SSRF where a user can cause the server to request attacker-controlled or unauthorized internal resources.
  - CSRF protections missing where state-changing browser requests rely on ambient credentials.
- **Remediation Standards:**
  - Enforce authorization server-side at the trust boundary before sensitive operations.
  - Derive identity and privilege from verified server-side session/token state, never from untrusted client claims.
  - Enforce object ownership/tenant scope for resource access.
  - Prefer deny-by-default policies and explicit allowlists.
  - Add CSRF protection where applicable.
  - For SSRF-prone flows, restrict destinations using allowlists and validate resolved addresses/redirects.

## A02:2025 - Security Misconfiguration

- **Detection Criteria:**
  - Hardcoded security-sensitive configuration, credentials, tokens, private keys, or passwords in source/configuration.
  - Debug/development features enabled in production.
  - Excessive error details or stack traces exposed to users.
  - Overly permissive CORS, cookies, security headers, filesystem/cloud permissions, or network exposure.
  - Default accounts/passwords, unnecessary services/features, sample applications, or unused endpoints enabled.
  - Insecure framework/server/database/cloud configuration.
  - XML parsers or similar components configured in ways that permit unsafe external entity processing.
  - Missing security hardening that can be directly evidenced from configuration.
- **Remediation Standards:**
  - Apply secure-by-default configuration and environment-specific hardening.
  - Keep secrets in environment-provided secret stores or dedicated secret-management systems; never commit them.
  - Disable debug features and sensitive stack traces in production.
  - Restrict CORS, cookies, security headers, service exposure, and cloud permissions to the minimum required.
  - Remove unnecessary services, sample applications, test accounts, and features.
  - Validate configuration in CI/CD where practical.

## A03:2025 - Software Supply Chain Failures

- **Detection Criteria:**
  - Dependencies with known vulnerabilities, unsupported/outdated components, or unsafe versions.
  - Missing or inconsistent lockfiles where deterministic dependency resolution is expected.
  - Untrusted package/source registries or suspicious dependency sources.
  - Unreviewed install/build scripts or dependency lifecycle hooks with excessive privileges.
  - Missing dependency inventory/SBOM where required by the workflow.
  - CI/CD or artifact-build steps that can be modified without appropriate controls.
  - Dependency updates or patches applied without compatibility tests.
- **Remediation Standards:**
  - Upgrade, replace, or remove vulnerable/unsupported dependencies using compatible versions.
  - Preserve and validate lockfiles and package integrity metadata.
  - Use trusted registries and pin dependencies appropriately.
  - Re-run dependency/security tests after updates.
  - Generate or update an SBOM when the project supports it.
  - Treat supply-chain changes as code changes: review, test, and verify provenance/integrity.

## A04:2025 - Cryptographic Failures

- **Detection Criteria:**
  - Weak or broken cryptographic algorithms/hashes used where stronger alternatives are required (e.g., MD5/SHA-1 for passwords or security-sensitive integrity).
  - Plaintext storage/transmission of sensitive data.
  - Hardcoded/reused cryptographic keys, predictable secrets, insecure IV/nonce handling, or unsafe random-number generation.
  - Insecure encryption modes (e.g., ECB) or unauthenticated encryption where integrity is required.
  - TLS/certificate validation disabled or weakened.
  - Missing key rotation or insecure key-management practices where evidenced.
- **Remediation Standards:**
  - Use current, purpose-appropriate cryptographic primitives and authenticated encryption.
  - Use adaptive password hashing such as Argon2, bcrypt, or PBKDF2 where appropriate.
  - Generate cryptographic randomness with platform-approved CSPRNGs.
  - Generate unique, unpredictable nonces/IVs as required by the chosen construction.
  - Keep cryptographic keys in secure secret/key-management systems.
  - Enforce TLS and proper certificate/hostname validation.

## A05:2025 - Injection

- **Detection Criteria:**
  - Untrusted input reaches SQL, NoSQL, LDAP, OS-command, template, expression, or other interpreter sinks without context-appropriate neutralization.
  - SQL/NoSQL queries constructed through unsafe concatenation/interpolation.
  - Command execution using attacker-controlled arguments or shell interpretation.
  - XSS caused by rendering untrusted content into HTML/DOM without appropriate encoding or sanitization.
  - Server-side template/expression injection.
  - Unsafe dynamic evaluation such as `eval()` or equivalent where attacker-controlled data can influence execution.
- **Remediation Standards:**
  - Use parameterized queries/prepared statements or safe ORM APIs.
  - Avoid shell interpretation; use structured argument APIs and strict allowlists.
  - Apply context-aware output encoding and framework-safe rendering.
  - Avoid dynamic code evaluation.
  - Sanitize HTML only when HTML input is intentionally supported and use a maintained, context-appropriate sanitizer.

## A06:2025 - Insecure Design

- **Detection Criteria:**
  - Business logic or workflow allows security-relevant state transitions without sufficient validation.
  - Security controls rely on client-side enforcement.
  - Missing abuse-case/threat-model considerations for sensitive workflows.
  - Missing rate limits, quotas, or anti-automation controls on security-sensitive operations where abuse is plausible.
  - Dangerous file-upload or workflow designs lacking defined security boundaries.
  - Trust-boundary violations or workflows that allow unexpected state transitions.
  - Excessive attack surface that can be evidenced from architecture or endpoint design.
- **Remediation Standards:**
  - Define and enforce security invariants at server-side trust boundaries.
  - Introduce threat modeling/abuse cases for high-risk workflows.
  - Add rate limiting, quotas, transaction/state validation, and explicit workflow controls where required.
  - Use secure design patterns and deny-by-default behavior.
  - Do NOT auto-patch complex business-logic/design findings unless the intended behavior is unambiguous and regression risk is low.

> **Automation limitation:** A06 is not fully machine-verifiable. Report design-level concerns with evidence and confidence rather than claiming definitive coverage.

## A07:2025 - Authentication Failures

- **Detection Criteria:**
  - Broken authentication flows, weak password handling, credential stuffing/brute-force exposure, or missing anti-automation controls where relevant.
  - Session fixation or failure to invalidate sessions/tokens after logout or security-sensitive events.
  - JWT/token validation weaknesses, including accepting insecure algorithms or insufficient signature validation.
  - Long-lived or insecurely stored authentication/session tokens.
  - Hardcoded authentication credentials.
  - Improper certificate/identity validation in authentication-related flows.
- **Remediation Standards:**
  - Use established authentication libraries and secure session mechanisms.
  - Enforce appropriate session expiry, rotation, revocation, and secure cookie attributes.
  - Validate token algorithms, issuer/audience/expiry and signatures according to the chosen protocol.
  - Store passwords using adaptive password hashing.
  - Add rate limiting or anti-automation protections where appropriate.

## A08:2025 - Software or Data Integrity Failures

- **Detection Criteria:**
  - Unsafe deserialization of untrusted data.
  - Dynamic object/property updates that allow unauthorized security-sensitive modification.
  - Consuming software/data updates or artifacts without integrity/authenticity verification.
  - Loading executable functionality from untrusted locations or control spheres.
  - Trusting critical data or update metadata without validation.
- **Remediation Standards:**
  - Avoid unsafe native deserialization; use constrained, schema-validated formats.
  - Validate and authorize security-sensitive object/property changes.
  - Verify signatures/checksums/provenance for trusted software or data artifacts where supported.
  - Restrict executable/plugin loading to trusted sources.
  - Validate schemas and trust boundaries before consuming external data.

## A09:2025 - Security Logging & Alerting Failures

- **Detection Criteria:**
  - Missing or inconsistent logging of security-relevant events such as failed logins, authorization violations, privilege changes, and high-value actions.
  - Sensitive data, tokens, passwords, or payment information written to logs.
  - Log injection or unsafe log formatting.
  - Logs stored only locally without appropriate retention/integrity controls where centralized logging is expected.
  - No actionable alerting path for important security events where the application is expected to provide one.
  - Errors or attacks occur without producing sufficient security telemetry.
- **Remediation Standards:**
  - Log security-relevant events with timestamps, actor/context, outcome, and correlation identifiers as appropriate.
  - Redact secrets and sensitive data.
  - Encode/sanitize log fields to prevent log injection.
  - Protect log integrity and define appropriate retention/centralization.
  - Add actionable alerting for high-value security events where supported by the architecture.

> **Automation limitation:** Code inspection can identify missing logging patterns, but cannot prove that production monitoring/alerting is operational.

## A10:2025 - Mishandling of Exceptional Conditions

- **Detection Criteria:**
  - Fail-open behavior after exceptions or validation failures.
  - Missing/null/invalid parameter handling that reaches security-sensitive logic.
  - Generic exception swallowing that bypasses security controls.
  - Sensitive information exposed through error responses.
  - Race conditions, state inconsistencies, resource exhaustion, or transaction failures that can violate security invariants.
  - Error paths that skip authorization, validation, cleanup, rollback, or security logging.
- **Remediation Standards:**
  - Fail closed for security-sensitive decisions and deny access when required state cannot be trusted.
  - Validate required parameters and exceptional states before sensitive operations.
  - Handle exceptions explicitly at the point of failure and provide safe user-facing errors.
  - Preserve transactional integrity and rollback state when partial operations fail.
  - Add security-relevant logging/alerting for abnormal conditions.
  - Avoid broad catch-and-ignore patterns.

---

## Audit Evidence Requirements

Every finding MUST include:
- OWASP category and, when confidently mappable, CWE.
- Exact file path and line/range or configuration location.
- Vulnerable code/configuration excerpt or a precise description of the evidence.
- Data flow or execution path when relevant.
- Exploit precondition and potential impact.
- Severity: `CRITICAL | HIGH | MEDIUM | LOW`.
- Confidence: `HIGH | MEDIUM | LOW`.
- Recommended remediation.
- Verification method.

The agent MUST distinguish:
- **Confirmed finding:** supported by direct static/runtime evidence.
- **Likely finding:** strong evidence but missing runtime/context confirmation.
- **Potential finding:** requires human review; do not auto-patch.

The agent MUST NOT report a vulnerability solely because a file/function name looks suspicious. Prefer evidence-based analysis over pattern-only matching.
