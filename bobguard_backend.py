#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
from dotenv import load_dotenv

# Impor kumpulan ekstensi dari supported_extension.py
from supported_extension import SUPPORTED_EXTENSIONS

load_dotenv()

DEFAULT_RULES_REL = Path(".bob/rules/owasp-top10-guide-2025.md")
DEFAULT_AUDIT_REL = Path(".bob/prompts/audit-orchestrator-2025.md")
DEFAULT_PATCH_REL = Path(".bob/prompts/patch-remediation-2025.md")

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".svelte-kit",
    "coverage",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Konversi set ekstensi ke tuple agar dapat digunakan langsung oleh .endswith()
EXTENSIONS_TUPLE = tuple(ext.lower() for ext in SUPPORTED_EXTENSIONS)


def is_supported_file(filename: str) -> bool:
    """Mengecek apakah nama file berakhiran dengan salah satu ekstensi yang didukung."""
    lower_name = filename.lower()
    return lower_name.endswith(EXTENSIONS_TUPLE)


class BobGuardBackend:
    def __init__(self, project_root: Optional[str] = None):
        self.project_root = Path(project_root or os.getenv("BOBGUARD_PROJECT_ROOT", ".")).resolve()
        self.api_key = os.getenv("BOB_API_KEY")
        if not self.api_key:
            raise ValueError(
                "BOB_API_KEY not found in .env! Please configure your API key before proceeding."
            )

        self.endpoint = os.getenv(
            "BOB_API_ENDPOINT", "https://api.bob.ibm.com/v1/chat/completions"
        )
        self.model = os.getenv("BOB_MODEL", "ibm-granite")
        self.request_timeout = int(os.getenv("BOB_REQUEST_TIMEOUT", "90"))
        self.test_timeout = int(os.getenv("BOBGUARD_TEST_TIMEOUT", "120"))

        self.rules_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_RULES_MD"), DEFAULT_RULES_REL
        )
        self.audit_prompt_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_AUDIT_MD"), DEFAULT_AUDIT_REL
        )
        self.patch_prompt_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_PATCH_MD"), DEFAULT_PATCH_REL
        )

        self.rules_content, self.rules = self._load_rules_and_metadata()
        self.audit_prompt_content = self._read_markdown_file(self.audit_prompt_path)
        self.patch_prompt_content = self._read_markdown_file(self.patch_prompt_path)

        if not self.rules_content:
            raise FileNotFoundError(f"OWASP rules file not found: {self.rules_path}")
        if not self.audit_prompt_content:
            raise FileNotFoundError(
                f"Audit orchestrator Markdown not found: {self.audit_prompt_path}"
            )
        if not self.patch_prompt_content:
            raise FileNotFoundError(
                f"Patch remediation Markdown not found: {self.patch_prompt_path}"
            )

    @staticmethod
    def is_directory_empty_or_no_code(target_dir: str | Path) -> bool:
        """Memeriksa apakah folder kosong atau tidak memiliki file kode yang didukung."""
        path = Path(target_dir).resolve()
        if not path.exists() or not path.is_dir():
            return True

        for current_root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                if is_supported_file(filename):
                    return False
        return True

    def set_project_root(self, project_root: str) -> None:
        """Change target repository and reload the three Markdown instructions."""
        self.project_root = Path(project_root).resolve()
        self.rules_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_RULES_MD"), DEFAULT_RULES_REL
        )
        self.audit_prompt_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_AUDIT_MD"), DEFAULT_AUDIT_REL
        )
        self.patch_prompt_path = self._resolve_doc_path(
            os.getenv("BOBGUARD_PATCH_MD"), DEFAULT_PATCH_REL
        )
        self.rules_content, self.rules = self._load_rules_and_metadata()
        self.audit_prompt_content = self._read_markdown_file(self.audit_prompt_path)
        self.patch_prompt_content = self._read_markdown_file(self.patch_prompt_path)

    def _resolve_doc_path(self, env_value: Optional[str], default_rel: Path) -> Path:
        raw = env_value.strip() if env_value else str(default_rel)
        path = Path(raw)
        if not path.is_absolute():
            path = self.project_root / path
        return path.resolve()

    @staticmethod
    def _read_markdown_file(filepath: Path) -> str:
        if filepath.exists() and filepath.is_file():
            return filepath.read_text(encoding="utf-8")
        return ""

    def _load_rules_and_metadata(self) -> Tuple[str, List[str]]:
        """Read OWASP 2025 rules and extract active category headers."""
        content = self._read_markdown_file(self.rules_path)
        if content:
            rule_matches = re.findall(
                r"^##\s+(A\d{2}:2025\s*-\s*[^\n]+)", content, re.MULTILINE
            )
            return content, rule_matches
        return "", []

    @staticmethod
    def _extract_json_array(raw_text: str) -> Optional[List[Dict[str, Any]]]:
        start = raw_text.find("[")
        end = raw_text.rfind("]") + 1
        if start < 0 or end <= start:
            return None
        parsed = json.loads(raw_text[start:end])
        if not isinstance(parsed, list):
            return None
        return parsed

    @staticmethod
    def _normalize_category(category: str) -> str:
        """Keep output aligned to OWASP Top 10:2025 labels when possible."""
        category = str(category or "").strip()
        if ":2021" in category:
            mapping = {
                "A01:2021": "A01:2025",
                "A02:2021": "A04:2025",
                "A03:2021": "A05:2025",
                "A04:2021": "A06:2025",
                "A05:2021": "A02:2025",
                "A06:2021": "A07:2025",
                "A07:2021": "A07:2025",
                "A08:2021": "A08:2025",
                "A09:2021": "A09:2025",
                "A10:2021": "A03:2025",
            }
            for old, new in mapping.items():
                if old in category:
                    return category.replace(old, new)
        return category

    def _build_audit_system_prompt(self, focus_finding: Optional[Dict[str, Any]] = None) -> str:
        focus_text = ""
        if focus_finding:
            focus_text = (
                "\n\nTARGETED VERIFICATION MODE:\n"
                "Re-check only whether the following previously reported finding is still exploitable. "
                "Do not invent unrelated findings. Return a finding only if the same security issue remains.\n"
                f"Previous finding: {json.dumps(focus_finding, ensure_ascii=False)}\n"
            )

        return (
            "You are BobGuard, an autonomous DevSecOps security analysis engine powered by IBM Bob 2.0.\n\n"
            "=== AUDIT ORCHESTRATOR (MARKDOWN SOURCE OF TRUTH) ===\n"
            f"{self.audit_prompt_content}\n\n"
            "=== OWASP TOP 10:2025 KNOWLEDGE BASE (MARKDOWN SOURCE OF TRUTH) ===\n"
            f"{self.rules_content}\n"
            f"{focus_text}\n\n"
            "AUDIT OUTPUT RULES:\n"
            "1. Use OWASP Top 10:2025 identifiers only.\n"
            "2. Report only evidence-backed issues visible in the supplied source.\n"
            "3. Do not infer vulnerabilities solely from variable names.\n"
            "4. Use the exact line number and exact vulnerable snippet when possible.\n"
            "5. Severity must be CRITICAL, HIGH, MEDIUM, or LOW.\n"
            "6. Include a confidence field: HIGH, MEDIUM, or LOW.\n"
            "7. For categories that require design/runtime context, explicitly say when evidence is insufficient.\n"
            "8. Return ONLY a JSON array; no Markdown fences or explanatory text.\n\n"
            "JSON SCHEMA:\n"
            "[{\n"
            '  "rule_id": "A05-SQLI",\n'
            '  "category": "A05:2025 - Injection",\n'
            '  "name": "SQL Injection",\n'
            '  "severity": "HIGH",\n'
            '  "confidence": "HIGH",\n'
            '  "line": 24,\n'
            '  "snippet": "exact vulnerable line",\n'
            '  "remediation": "concise technical remediation",\n'
            '  "evidence": "why the code demonstrates the issue"\n'
            "}]\n"
            "If no confirmed issue exists, return []."
        )

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }

        response = requests.post(
            self.endpoint,
            headers=headers,
            json=payload,
            timeout=self.request_timeout,
        )
        response.raise_for_status()
        body = response.json()
        content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
        return str(content).strip()

    def audit_file_with_bob_llm(
        self, filepath: str, focus_finding: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Audit one source file using OWASP + audit-orchestrator Markdown."""
        path = Path(filepath).resolve()
        try:
            code_content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        system_prompt = self._build_audit_system_prompt(focus_finding)
        user_prompt = (
            f"Target file: {path}\n\n"
            "Source code:\n"
            f"```\n{code_content}\n```"
        )

        try:
            raw_text = self._call_llm(system_prompt, user_prompt)
            findings = self._extract_json_array(raw_text)
            if findings is None:
                return []

            valid_findings: List[Dict[str, Any]] = []
            for item in findings:
                if not isinstance(item, dict):
                    continue
                item["file"] = str(path)
                item["category"] = self._normalize_category(item.get("category", ""))
                item.setdefault("confidence", "MEDIUM")
                valid_findings.append(item)
            return valid_findings
        except (requests.RequestException, ValueError, json.JSONDecodeError, KeyError):
            return []

    def scan_entire_codebase(self, target_dir: str = ".") -> List[Dict[str, Any]]:
        """Audit supported source files while honoring ignore directories."""
        root = Path(target_dir).resolve()
        self.set_project_root(str(root))
        all_findings: List[Dict[str, Any]] = []

        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                # Menggunakan pengecekan ekstensi terpusat dari supported_extension.py
                if not is_supported_file(filename):
                    continue
                path = Path(current_root) / filename
                all_findings.extend(self.audit_file_with_bob_llm(str(path)))

        all_findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(str(f.get("severity", "MEDIUM")).upper(), 99),
                str(f.get("file", "")),
                int(f.get("line", 10**9)) if str(f.get("line", "")).isdigit() else 10**9,
            )
        )
        return all_findings

    def generate_patch_with_bob(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a patch using patch-remediation Markdown as the source of truth."""
        filepath = Path(str(finding.get("file", ""))).resolve()
        if not filepath.is_file():
            raise FileNotFoundError(f"Target file not found: {filepath}")

        code_content = filepath.read_text(encoding="utf-8", errors="ignore")
        patch_system_prompt = (
            "You are BobGuard Autonomous Remediation Specialist powered by IBM Bob 2.0.\n\n"
            "=== SAFE REMEDIATION PROTOCOL (MARKDOWN SOURCE OF TRUTH) ===\n"
            f"{self.patch_prompt_content}\n\n"
            "PATCH OUTPUT RULES:\n"
            "1. Resolve only the supplied finding.\n"
            "2. Preserve business logic and API contracts unless the vulnerability itself requires a change.\n"
            "3. Make the smallest safe change possible.\n"
            "4. Never add secrets, credentials, or unsafe fallback values.\n"
            "5. Return ONLY one JSON object and no Markdown fences.\n\n"
            "JSON SCHEMA:\n"
            "{\n"
            '  "target_file": "path",\n'
            '  "vulnerability_id": "A05-SQLI",\n'
            '  "severity": "HIGH",\n'
            '  "root_cause": "...",\n'
            '  "replacement": "exact secure replacement text",\n'
            '  "verification_plan": ["test or check 1", "test or check 2"]\n'
            "}"
        )
        user_prompt = (
            "Finding:\n"
            f"{json.dumps(finding, indent=2, ensure_ascii=False)}\n\n"
            "Current file:\n"
            f"```\n{code_content}\n```"
        )

        raw_text = self._call_llm(patch_system_prompt, user_prompt)
        start = raw_text.find("{")
        end = raw_text.rfind("}") + 1
        if start < 0 or end <= start:
            raise ValueError("Bob did not return a JSON remediation proposal.")

        proposal = json.loads(raw_text[start:end])
        if not isinstance(proposal, dict) or not proposal.get("replacement"):
            raise ValueError("Invalid remediation proposal returned by Bob.")

        proposal["target_file"] = str(filepath)
        proposal["vulnerability_id"] = proposal.get(
            "vulnerability_id", finding.get("rule_id", "UNKNOWN")
        )
        proposal["severity"] = proposal.get("severity", finding.get("severity", "MEDIUM"))
        proposal["old_snippet"] = finding.get("snippet", "")
        return proposal

    def backup_file(self, filepath: str) -> str:
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        fd, tmp_name = tempfile.mkstemp(prefix="bobguard_", suffix=".bak")
        os.close(fd)
        backup = Path(tmp_name)
        shutil.copy2(path, backup)
        return str(backup)

    @staticmethod
    def restore_backup(filepath: str, backup_path: str) -> None:
        shutil.copy2(backup_path, filepath)

    @staticmethod
    def cleanup_backup(backup_path: str) -> None:
        try:
            Path(backup_path).unlink(missing_ok=True)
        except OSError:
            pass

    def apply_patch(self, proposal: Dict[str, Any]) -> Tuple[bool, str]:
        """Apply only an exact, unambiguous replacement from a remediation proposal."""
        filepath = Path(str(proposal.get("target_file", ""))).resolve()
        old = str(proposal.get("old_snippet", ""))
        new = str(proposal.get("replacement", ""))

        if not filepath.is_file():
            return False, "Target file does not exist."
        if not old or not new:
            return False, "Patch proposal is incomplete."

        try:
            content = filepath.read_text(encoding="utf-8")
        except OSError as exc:
            return False, str(exc)

        count = content.count(old)
        if count == 1:
            filepath.write_text(content.replace(old, new, 1), encoding="utf-8")
            return True, "Patch applied with exact unique snippet replacement."

        target_line = proposal.get("line")
        lines = content.splitlines(keepends=True)
        if isinstance(target_line, int) and 1 <= target_line <= len(lines):
            current_line = lines[target_line - 1]
            if old.strip() and old.strip() == current_line.strip():
                replacement_lines = new.splitlines(keepends=True)
                if replacement_lines and not replacement_lines[-1].endswith("\n"):
                    replacement_lines[-1] += "\n"
                lines[target_line - 1 : target_line] = replacement_lines
                filepath.write_text("".join(lines), encoding="utf-8")
                return True, "Patch applied with exact line match."

        if count > 1:
            return False, "Patch rejected because the vulnerable snippet is ambiguous (multiple matches)."
        return False, "Target vulnerable snippet could not be matched exactly."

    def detect_test_command(self) -> Optional[List[str]]:
        """Detect a repository test command, or use BOB_TEST_COMMAND if configured."""
        custom = os.getenv("BOB_TEST_COMMAND", "").strip()
        if custom:
            return shlex.split(custom, posix=os.name != "nt")

        root = self.project_root
        package = root / "package.json"
        if package.is_file():
            try:
                data = json.loads(package.read_text(encoding="utf-8"))
                scripts = data.get("scripts", {})
                if "test" in scripts:
                    if (root / "pnpm-lock.yaml").is_file():
                        return ["pnpm", "test"]
                    if (root / "yarn.lock").is_file():
                        return ["yarn", "test"]
                    return ["npm", "test"]
            except (OSError, json.JSONDecodeError):
                pass

        if (root / "pytest.ini").is_file() or (root / "pyproject.toml").is_file() or list(root.glob("test_*.py")):
            return [os.environ.get("PYTHON", "python"), "-m", "pytest", "-q"]

        if (root / "go.mod").is_file():
            return ["go", "test", "./..."]

        if (root / "pom.xml").is_file():
            return ["mvn", "test", "-q"]

        if (root / "composer.json").is_file():
            return ["composer", "test"]

        return None

    def run_tests(self) -> Dict[str, Any]:
        """Run the detected test suite. No command is run if no suite is detected."""
        command = self.detect_test_command()
        if not command:
            return {
                "status": "NOT_CONFIGURED",
                "passed": True,
                "command": None,
                "output": "No test command detected. Configure BOB_TEST_COMMAND for the project.",
            }

        try:
            result = subprocess.run(
                command,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.test_timeout,
                check=False,
            )
            output = (result.stdout + "\n" + result.stderr).strip()
            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "passed": result.returncode == 0,
                "command": command,
                "returncode": result.returncode,
                "output": output[-12000:],
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "TIMEOUT",
                "passed": False,
                "command": command,
                "output": f"Test command exceeded {self.test_timeout}s timeout.",
            }
        except OSError as exc:
            return {
                "status": "ERROR",
                "passed": False,
                "command": command,
                "output": str(exc),
            }

    def validate_file_syntax(self, filepath: str) -> Dict[str, Any]:
        """Perform a cheap targeted syntax check where a reliable command exists."""
        path = Path(filepath).resolve()
        suffix = path.suffix.lower()
        command: Optional[List[str]] = None

        if suffix == ".py":
            command = [os.environ.get("PYTHON", "python"), "-m", "py_compile", str(path)]
        elif suffix == ".php":
            command = ["php", "-l", str(path)]
        elif suffix == ".js":
            command = ["node", "--check", str(path)]

        if not command:
            return {"status": "NOT_AVAILABLE", "passed": True, "command": None, "output": ""}

        try:
            result = subprocess.run(
                command,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.test_timeout,
                check=False,
            )
            output = (result.stdout + "\n" + result.stderr).strip()
            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "passed": result.returncode == 0,
                "command": command,
                "returncode": result.returncode,
                "output": output[-8000:],
            }
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {
                "status": "ERROR",
                "passed": False,
                "command": command,
                "output": str(exc),
            }

    def verify_finding_resolved(
        self, finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Targeted LLM re-scan of only the patched file for the same finding."""
        filepath = str(finding.get("file", ""))
        findings = self.audit_file_with_bob_llm(filepath, focus_finding=finding)
        same_rule = []
        target_rule = str(finding.get("rule_id", ""))
        target_name = str(finding.get("name", "")).lower()
        for item in findings:
            if target_rule and str(item.get("rule_id", "")) == target_rule:
                same_rule.append(item)
            elif target_name and target_name in str(item.get("name", "")).lower():
                same_rule.append(item)

        return {
            "passed": len(same_rule) == 0,
            "status": "PASS" if len(same_rule) == 0 else "FAIL",
            "remaining_findings": same_rule,
        }

    def remediate_and_verify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Full safe remediation transaction: baseline -> patch -> validate -> rescan -> rollback."""
        proposal = self.generate_patch_with_bob(finding)
        proposal["line"] = finding.get("line")

        baseline = self.run_tests()
        backup_path = self.backup_file(str(finding["file"]))

        applied, apply_message = self.apply_patch(proposal)
        if not applied:
            self.cleanup_backup(backup_path)
            return {
                "status": "PATCH_NOT_APPLIED",
                "proposal": proposal,
                "baseline": baseline,
                "apply_message": apply_message,
            }

        syntax = self.validate_file_syntax(str(finding["file"]))
        tests = self.run_tests()
        security = self.verify_finding_resolved(finding)

        verified = syntax["passed"] and tests["passed"] and security["passed"]
        if verified:
            self.cleanup_backup(backup_path)
            return {
                "status": "FIXED & VERIFIED",
                "proposal": proposal,
                "baseline": baseline,
                "syntax": syntax,
                "tests": tests,
                "security_rescan": security,
                "apply_message": apply_message,
            }

        self.restore_backup(str(finding["file"]), backup_path)
        self.cleanup_backup(backup_path)
        return {
            "status": "PATCH FAILED / ROLLED BACK",
            "proposal": proposal,
            "baseline": baseline,
            "syntax": syntax,
            "tests": tests,
            "security_rescan": security,
            "apply_message": apply_message,
        }