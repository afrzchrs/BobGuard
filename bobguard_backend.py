#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from supported_extension import SUPPORTED_EXTENSIONS
from dotenv import load_dotenv

APP_ROOT = Path(__file__).resolve().parent
load_dotenv(dotenv_path=APP_ROOT / ".env", override=False)

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
EXTENSIONS_TUPLE = tuple(ext.lower() for ext in SUPPORTED_EXTENSIONS)


def is_supported_file(filename: str) -> bool:
    """Mengecek apakah file cocok dengan ekstensi yang didukung."""
    return filename.lower().endswith(EXTENSIONS_TUPLE)


TEST_DIR_NAMES = {"tests", "test"}
TEST_FILE_PREFIXES = ("test_",)


def is_test_file(path: str | Path, project_root: str | Path) -> bool:
    """Return True for test files that should be evidence only, not remediation targets."""
    target = Path(path).resolve()
    root = Path(project_root).resolve()

    try:
        relative = target.relative_to(root)
    except ValueError:
        relative = Path(target.name)

    if any(part.lower() in TEST_DIR_NAMES for part in relative.parts[:-1]):
        return True

    return relative.name.lower().startswith(TEST_FILE_PREFIXES)


class BobGuardBackend:
    def __init__(self, project_root: Optional[str] = None):
        self.project_root = Path(project_root or os.getenv("BOBGUARD_PROJECT_ROOT", "sample-app")).resolve()
        api_key = os.getenv("BOB_API_KEY")
        if not api_key:
            raise ValueError(
                "BOB_API_KEY not found in .env! Please configure your API key before proceeding."
            )
        self.api_key: str = api_key.strip()

        self.request_timeout = int(os.getenv("BOB_REQUEST_TIMEOUT", "90"))
        self.test_timeout = int(os.getenv("BOBGUARD_TEST_TIMEOUT", "120"))

        # Mengambil file dokumen dari APP_ROOT (.bob di root BobGuard)
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
        """Mengubah repositori target tanpa merusak path dokumen .bob."""
        self.project_root = Path(project_root).resolve()

    def _resolve_doc_path(self, env_value: Optional[str], default_rel: Path) -> Path:
        """
        Mencari file aturan dengan prioritas ke APP_ROOT 
        dan mendukung variasi nama file (dengan atau tanpa '-2025').
        """
        raw = env_value.strip() if env_value else str(default_rel)
        path = Path(raw)
        if path.is_absolute() and path.exists():
            return path.resolve()

        # Kandidat nama file alternatif (misal: 'owasp-top10-guide.md' vs 'owasp-top10-guide-2025.md')
        alt_name = (
            path.name.replace("-2025", "")
            if "-2025" in path.name
            else path.name.replace(".md", "-2025.md")
        )

        candidates = [
            APP_ROOT / path,
            APP_ROOT / path.parent / alt_name,
            self.project_root / path,
            self.project_root / path.parent / alt_name,
        ]

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()

        return (APP_ROOT / path).resolve()

    @staticmethod
    def _read_markdown_file(filepath: Path) -> str:
        if filepath.exists() and filepath.is_file():
            return filepath.read_text(encoding="utf-8")
        return ""

    def _load_rules_and_metadata(self) -> Tuple[str, List[str]]:
        """Membaca aturan OWASP dan mengekstrak kategori aktif."""
        content = self._read_markdown_file(self.rules_path)
        if content:
            rule_matches = re.findall(
                r"^##\s+(A\d{2}:2025\s*-\s*[^\n]+)", content, re.MULTILINE
            )
            return content, rule_matches
        return "", []

    @staticmethod
    def _extract_bob_message(raw_text: str) -> str:
        """Extract Bob's last_message from JSON or JSON-lines output."""
        text = raw_text.strip()
        if not text:
            return ""

        # Normal --format json output: one JSON object.
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                if parsed.get("type") == "error":
                    raise RuntimeError(
                        str(
                            parsed.get("message")
                            or parsed.get("error")
                            or "Bob Shell returned an error."
                        )
                    )
                last_message = parsed.get("last_message")
                if isinstance(last_message, str):
                    return last_message.strip()
        except json.JSONDecodeError:
            pass

        # Be tolerant of multiple JSON events (e.g. error + result).
        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)

        errors = [event for event in events if event.get("type") == "error"]
        if errors:
            message = errors[-1].get("message") or errors[-1].get("error")
            raise RuntimeError(str(message or "Bob Shell returned an error."))

        for event in reversed(events):
            last_message = event.get("last_message")
            if isinstance(last_message, str):
                return last_message.strip()

        return text

    @classmethod
    def _extract_json_array(
        cls, raw_text: str
    ) -> Optional[List[Dict[str, Any]]]:
        """Extract an audit JSON array without being confused by Markdown links."""
        text = cls._extract_bob_message(raw_text).strip()
        if not text:
            return None

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

        fenced = re.search(
            r"```(?:json)?\s*(\[[\s\S]*?\])\s*```",
            text,
            flags=re.IGNORECASE,
        )
        if fenced:
            try:
                parsed = json.loads(fenced.group(1))
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass

        decoder = json.JSONDecoder()
        for match in re.finditer(r"\[", text):
            try:
                parsed, _ = decoder.raw_decode(text[match.start():])
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                continue

        return None

    @staticmethod
    def _sanitize_json_string_controls(text: str) -> str:
        """
        Escape raw control characters that sometimes appear inside LLM JSON strings.
        Valid JSON requires newline/tab characters inside strings to be escaped as
        \\n / \\t rather than embedded literally.
        """
        out: List[str] = []
        in_string = False
        escaped = False

        for char in text:
            if escaped:
                out.append(char)
                escaped = False
                continue

            if char == "\\\\":
                out.append(char)
                if in_string:
                    escaped = True
                continue

            if char == '"':
                out.append(char)
                in_string = not in_string
                continue

            if in_string:
                if char == "\n":
                    out.append("\\n")
                elif char == "\r":
                    out.append("\\r")
                elif char == "\t":
                    out.append("\\t")
                elif ord(char) < 0x20:
                    out.append(f"\\u{ord(char):04x}")
                else:
                    out.append(char)
            else:
                out.append(char)

        return "".join(out)

    @staticmethod
    def _extract_balanced_json_object(text: str) -> Optional[str]:
        """Return the first balanced JSON object, respecting quoted strings."""
        start = text.find("{")
        while start != -1:
            depth = 0
            in_string = False
            escaped = False

            for index in range(start, len(text)):
                char = text[index]

                if escaped:
                    escaped = False
                    continue

                if char == "\\\\" and in_string:
                    escaped = True
                    continue

                if char == '"':
                    in_string = not in_string
                    continue

                if in_string:
                    continue

                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start:index + 1]

            start = text.find("{", start + 1)

        return None

    @classmethod
    def _extract_json_object(
        cls, raw_text: str
    ) -> Optional[Dict[str, Any]]:
        """Extract one remediation JSON object from Bob's response."""
        text = cls._extract_bob_message(raw_text).strip()
        if not text:
            return None

        candidates = [text]

        fenced = re.search(
            r"```(?:json)?\s*([\s\S]*?)\s*```",
            text,
            flags=re.IGNORECASE,
        )
        if fenced:
            candidates.insert(0, fenced.group(1).strip())

        balanced = cls._extract_balanced_json_object(text)
        if balanced:
            candidates.append(balanced)

        seen = set()
        for candidate in candidates:
            candidate = candidate.strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)

            for payload in (
                candidate,
                cls._sanitize_json_string_controls(candidate),
            ):
                try:
                    parsed = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    return parsed

        return None

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
            "=== OWASP KNOWLEDGE BASE (MARKDOWN SOURCE OF TRUTH) ===\n"
            f"{self.rules_content}\n"
            f"{focus_text}\n\n"
            "AUDIT OUTPUT RULES:\n"
            "1. Report only evidence-backed issues visible in the supplied source.\n"
            "2. Use the exact line number and exact vulnerable snippet when possible.\n"
            "3. Severity must be CRITICAL, HIGH, MEDIUM, or LOW.\n"
            "4. Include a confidence field: HIGH, MEDIUM, or LOW.\n"
            "5. Return ONLY a valid JSON array; no Markdown code fences or extra text.\n\n"
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

    def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        mode: str = "ask",
        allow_workspace_edit: bool = False,
    ) -> str:
        """
        Memanggil IBM Bob Shell secara non-interaktif.

        Audit:
          --mode ask
        Remediation JSON:
          --mode agent

        Semua source code sudah diberikan melalui stdin, sehingga Bob tidak
        perlu membaca/mengubah/menjalankan workspace.
        """

        combined_prompt = (
            f"{system_prompt}\n\n"
            f"=== USER REQUEST & CODE TO AUDIT ===\n"
            f"{user_prompt}"
        )

        env: dict[str, str] = os.environ.copy()
        env["BOB_API_KEY"] = self.api_key

        bob_bin = shutil.which("bob")
        if not bob_bin:
            raise RuntimeError(
                "Perintah 'bob' tidak ditemukan di PATH. "
                "Pastikan 'bob --version' dapat dijalankan."
            )

        cmd = [
            bob_bin,
            "run",
            "--format",
            "json",
            "--mode",
            mode,
        ]

        if allow_workspace_edit:
            # Agent mode gets real read/edit access to the target workspace.
            # Keep shell/execute and external integrations disabled so Bob can
            # modify source files but cannot run arbitrary commands.
            cmd.extend([
                "--disable-tool-groups",
                "execute,mcp,skill,todo,subagent,mode",
            ])
        else:
            # Audit mode stays read-only and deterministic.
            cmd.extend([
                "--disable-tool-groups",
                "read,edit,execute,mcp,skill,todo,subagent,mode",
            ])

        cmd.extend([
            "--max-cost",
            os.getenv("BOB_MAX_COST", "0.75"),
            "--max-turns",
            os.getenv(
                "BOB_AUDIT_MAX_TURNS" if mode == "ask" else "BOB_PATCH_MAX_TURNS",
                "2" if mode == "ask" else "4",
            ),
        ])

        try:
            result = subprocess.run(
                cmd,
                input=combined_prompt,
                env=env,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.request_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Bob Shell timeout setelah {self.request_timeout} detik."
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Gagal menjalankan Bob Shell: {exc}") from exc

        output = result.stdout.strip()

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(
                "Bob Shell gagal menjalankan request.\n"
                f"Mode: {mode}\n"
                f"Exit code: {result.returncode}\n"
                f"Stderr: {stderr or '(tidak ada stderr)'}\n"
                f"Output: {output[:2000] if output else '(kosong)'}"
            )

        if not output:
            raise RuntimeError("Bob Shell mengembalikan output kosong.")

        return output

    def audit_file_with_bob_llm(
        self, filepath: str, focus_finding: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        path = Path(filepath).resolve()
        try:
            code_content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        print(f"[dim]→ Sending {path.name} to IBM Bob LLM...[/dim]")

        system_prompt = self._build_audit_system_prompt(focus_finding)
        user_prompt = f"Target file: {path}\n\nSource code:\n```\n{code_content}\n```"

        try:
            raw_text = self._call_llm(system_prompt, user_prompt, mode="ask")
            if not raw_text:
                return []

            findings = self._extract_json_array(raw_text)
            if findings is None:
                # Menampilkan output asli jika format JSON tidak terbaca
                print(f"\n[DEBUG] Output dari Bob Shell untuk {path.name} bukan JSON array murni:")
                print(raw_text[:500] + ("..." if len(raw_text) > 500 else ""))
                return []

            valid_findings: List[Dict[str, Any]] = []
            for item in findings:
                if not isinstance(item, dict):
                    continue
                item["file"] = str(path)
                item.setdefault("confidence", "MEDIUM")
                valid_findings.append(item)
            return valid_findings

        except Exception as e:
            print(f"[ERROR] Exception during audit of {path.name}: {e}")
            return []

    def scan_entire_codebase(self, target_dir: str = "sample-app") -> List[Dict[str, Any]]:
        root = Path(target_dir).resolve()
        self.set_project_root(str(root))
        all_findings: List[Dict[str, Any]] = []

        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                if not is_supported_file(filename):
                    continue
                path = Path(current_root) / filename
                # Security tests are verification/evidence, not remediation targets.
                if is_test_file(path, root):
                    continue
                all_findings.extend(self.audit_file_with_bob_llm(str(path)))

        all_findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(str(f.get("severity", "MEDIUM")).upper(), 99),
                str(f.get("file", "")),
                int(f.get("line", 10**9)) if str(f.get("line", "")).isdigit() else 10**9,
            )
        )
        return all_findings

    @staticmethod
    def _extract_unified_diff_proposal(
        raw_text: str,
        filepath: Path,
        finding: Dict[str, Any],
        code_content: str,
    ) -> Optional[Dict[str, Any]]:
        """Convert Bob's Markdown unified-diff preview into a safe patch proposal."""
        text = BobGuardBackend._extract_bob_message(raw_text).strip()
        if not text:
            return None
        match = re.search(r"```diff\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
        diff = match.group(1) if match else text
        removed: List[str] = []
        added: List[str] = []
        in_hunk = False
        for line in diff.splitlines():
            if line.startswith("@@"):
                in_hunk = True
                continue
            if not in_hunk:
                continue
            if line.startswith("--- ") or line.startswith("+++ "):
                continue
            if line.startswith("-"):
                removed.append(line[1:])
            elif line.startswith("+"):
                added.append(line[1:])
        if not removed or not added:
            return None
        old = "\n".join(removed).strip()
        new = "\n".join(added).strip()
        if not old or not new:
            return None
        if old not in code_content:
            line_no = finding.get("line")
            if isinstance(line_no, int) and 1 <= line_no <= len(code_content.splitlines()):
                candidate = code_content.splitlines()[line_no - 1].strip()
                if candidate and candidate in old and candidate in code_content:
                    old = candidate
                else:
                    return None
            else:
                return None
        return {
            "target_file": str(filepath),
            "vulnerability_id": finding.get("rule_id", "UNKNOWN"),
            "severity": finding.get("severity", "MEDIUM"),
            "root_cause": finding.get("evidence", "Derived from the supplied finding and Bob unified diff."),
            "replacement": new,
            "verification_plan": [
                "Validate target file syntax.",
                "Run the configured test suite.",
                "Re-run targeted security verification.",
            ],
            "old_snippet": old,
            "line": finding.get("line"),
            "source": "unified-diff-fallback",
        }

    @staticmethod
    def _file_digest(path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _snapshot_workspace(self) -> Dict[str, bytes]:
        """Snapshot all non-ignored workspace files for safe agent rollback."""
        snapshot: Dict[str, bytes] = {}
        for current_root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                path = Path(current_root) / filename
                try:
                    snapshot[str(path.resolve())] = path.read_bytes()
                except OSError:
                    pass
        return snapshot

    @staticmethod
    def _changed_paths(before: Dict[str, bytes], after: Dict[str, bytes]) -> List[str]:
        """Return workspace paths whose content was created, deleted, or modified."""
        changed = []
        for path in sorted(set(before) | set(after)):
            if before.get(path) != after.get(path):
                changed.append(path)
        return changed

    def _restore_workspace(self, snapshot: Dict[str, bytes]) -> None:
        """Restore the complete non-ignored workspace content."""
        current: Dict[str, bytes] = {}
        for current_root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                path = Path(current_root) / filename
                try:
                    current[str(path.resolve())] = path.read_bytes()
                except OSError:
                    pass

        for path_str, content in snapshot.items():
            path = Path(path_str)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            except OSError:
                pass

        for path_str in set(current) - set(snapshot):
            try:
                Path(path_str).unlink(missing_ok=True)
            except OSError:
                pass

    def _snapshot_supported_files(self) -> Dict[str, bytes]:
        snapshot: Dict[str, bytes] = {}
        for current_root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                if not is_supported_file(filename):
                    continue
                path = Path(current_root) / filename
                try:
                    snapshot[str(path.resolve())] = path.read_bytes()
                except OSError:
                    pass
        return snapshot

    def _restore_snapshot(self, snapshot: Dict[str, bytes]) -> None:
        current_paths = set()
        for current_root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for filename in files:
                if is_supported_file(filename):
                    current_paths.add(str((Path(current_root) / filename).resolve()))

        for path_str, content in snapshot.items():
            path = Path(path_str)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            except OSError:
                pass

        for path_str in current_paths - set(snapshot):
            try:
                Path(path_str).unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _extract_test_failure_ids(output: str) -> set[str]:
        failures = set()
        for match in re.finditer(r"(?m)^FAILED\s+([^\s]+)", output or ""):
            failures.add(match.group(1).strip())
        for match in re.finditer(r"(?m)^ERROR\s+([^\s]+)", output or ""):
            failures.add("ERROR:" + match.group(1).strip())
        return failures

    @staticmethod
    def _failure_signature(output: str) -> str:
        """Create a normalized signature for diagnostics when strict mode is requested."""
        import hashlib

        text = output or ""
        if "FAILURES" in text:
            text = text.split("FAILURES", 1)[1]
        if "short test summary info" in text:
            text = text.split("short test summary info", 1)[0]

        lines = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if re.match(r"^[.=]+\s*\d+%", line):
                continue
            line = re.sub(r"([A-Za-z0-9_./\\-]+\.py):\d+", r"\1:<line>", line)
            line = re.sub(r"\b\d+ passed,?\s*\d+ failed.*", "", line)
            line = re.sub(r"\b\d+ passed.*", "", line)
            if line:
                lines.append(line)
        return hashlib.sha256("\n".join(lines).encode("utf-8", "replace")).hexdigest()

    @staticmethod
    def _test_regression(baseline: Dict[str, Any], post: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare pytest by failing test identity, not by the whole report hash.

        In the vulnerable demo app, remediation is expected to turn some
        previously failing security tests into passes. A whole-report hash
        therefore changes by design and must not be treated as a regression.
        """
        baseline_output = baseline.get("output", "")
        post_output = post.get("output", "")
        baseline_failures = BobGuardBackend._extract_test_failure_ids(baseline_output)
        post_failures = BobGuardBackend._extract_test_failure_ids(post_output)
        new_failures = sorted(post_failures - baseline_failures)
        resolved_failures = sorted(baseline_failures - post_failures)

        # Default policy: a regression is a NEW failing test. Existing failing
        # tests are expected to remain until their own finding is remediated.
        diagnostics_changed = False
        strict_mode = os.getenv("BOBGUARD_STRICT_EXISTING_FAILURES", "0") == "1"
        if strict_mode and baseline_failures and post_failures:
            # The legacy global signature was too strict: resolving one failure
            # necessarily changed the report. In strict mode we only compare
            # reports when the exact same failure set is still present.
            if baseline_failures == post_failures:
                baseline_sig = BobGuardBackend._failure_signature(baseline_output)
                post_sig = BobGuardBackend._failure_signature(post_output)
                diagnostics_changed = baseline_sig != post_sig

        passed = not new_failures and not diagnostics_changed
        status = "NO_NEW_REGRESSIONS" if passed else "REGRESSION"

        return {
            "passed": passed,
            "status": status,
            "baseline_failures": sorted(baseline_failures),
            "post_failures": sorted(post_failures),
            "new_failures": new_failures,
            "resolved_failures": resolved_failures,
            "existing_failure_diagnostics_changed": diagnostics_changed,
            "strict_existing_failure_check": strict_mode,
        }

    def _agent_edit_file(self, finding: Dict[str, Any], retry_reason: str = "") -> Dict[str, Any]:
        filepath = Path(str(finding.get("file", ""))).resolve()
        if is_test_file(filepath, self.project_root):
            raise ValueError(
                f"Refusing to modify test file: {filepath}. "
                "Security tests are evidence, not remediation targets."
            )
        if not filepath.is_file():
            raise FileNotFoundError(f"Target file not found: {filepath}")

        relative_target = filepath.relative_to(self.project_root).as_posix()
        system_prompt = (
            "You are BobGuard Autonomous Remediation Agent powered by IBM Bob 2.0.\n\n"
            "Your job is to FIX the supplied security finding by editing the workspace directly.\n"
            "You have read and edit tools available. Use them; do not merely describe a patch.\n"
            "Read the target file and any directly relevant dependency file only when needed.\n"
            "Modify ONLY the target file. Do not modify tests, configuration, documentation, or other files.\n"
            "Make the smallest safe remediation that preserves the existing API and business behavior.\n"
            "Do not run shell commands; execution tools are intentionally disabled.\n"
            "After editing, stop. The BobGuard controller will run syntax checks, tests, and a security rescan.\n"
            "ABSOLUTE CONSTRAINT: edit exactly one file: the target file named below.\n"
            "Never edit tests, config, documentation, lockfiles, generated files, or any other file.\n\n"
            + (f"PREVIOUS ATTEMPT VIOLATION: {retry_reason}\n" if retry_reason else "")
            + "=== SAFE REMEDIATION PROTOCOL ===\n"
            f"{self.patch_prompt_content}\n\n"
            "=== TARGET ===\n"
            f"File: {relative_target}\n"
            f"Finding: {json.dumps(finding, ensure_ascii=False)}\n"
        )
        user_prompt = (
            "Apply the remediation directly to the target file now.\n"
            "Do not return a diff as the primary deliverable; the file modification is the deliverable.\n"
            "Do not create or edit any other file.\n"
        )

        before = filepath.read_bytes()
        raw = self._call_llm(
            system_prompt,
            user_prompt,
            mode="agent",
            allow_workspace_edit=True,
        )
        after = filepath.read_bytes() if filepath.exists() else b""
        changed = before != after

        if not changed:
            debug = self._extract_bob_message(raw)[:3000]
            raise ValueError(
                "Bob Agent finished without modifying the target file.\n"
                f"Bob message: {debug}"
            )

        return {
            "target_file": str(filepath),
            "vulnerability_id": finding.get("rule_id", "UNKNOWN"),
            "severity": finding.get("severity", "MEDIUM"),
            "root_cause": finding.get("evidence", ""),
            "source": "bob-agent-direct-edit",
            "agent_message": self._extract_bob_message(raw)[:4000],
        }

    def generate_patch_with_bob(self, finding: Dict[str, Any]) -> Dict[str, Any]:
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
            "2. Preserve business logic and API contracts.\n"
            "3. Make the smallest safe change possible.\n"
            "4. Return ONLY one valid JSON object and no Markdown code fences.\n5. JSON string values MUST use escaped newlines (\\\\n), never literal line breaks.\n6. Do NOT attempt to read, edit, execute, or call tools; the complete target file is already included below.\n7. Do not emit tool_use blocks, analysis steps, or a unified diff; output the JSON object directly.\n\n"
            "JSON SCHEMA:\n"
            "{\n"
            '  "target_file": "path",\n'
            '  "vulnerability_id": "A05-SQLI",\n'
            '  "severity": "HIGH",\n'
            '  "root_cause": "...",\n'
            '  "replacement": "exact secure replacement text",\n'
            '  "verification_plan": ["test or check 1"]\n'
            "}"
        )
        user_prompt = (
            "Finding:\n"
            f"{json.dumps(finding, indent=2, ensure_ascii=False)}\n\n"
            "Current file:\n"
            f"```\n{code_content}\n```"
        )

        raw_text = self._call_llm(patch_system_prompt, user_prompt, mode="agent")
        proposal = self._extract_json_object(raw_text)
        if proposal is None:
            proposal = self._extract_unified_diff_proposal(
                raw_text, filepath, finding, code_content
            )

        if proposal is None:
            retry_prompt = (
                patch_system_prompt
                + "\nIMPORTANT RETRY: Output ONLY the JSON object itself. "
                + "Do not mention Ask mode, permissions, or inability to edit. "
                + "Do not explain, do not use Markdown fences, do not add commentary. "
                + "Never use tool_use blocks. The first character must be { and the last character must be }."
            )
            raw_retry = self._call_llm(retry_prompt, user_prompt, mode="agent")
            proposal = self._extract_json_object(raw_retry)
            if proposal is None:
                proposal = self._extract_unified_diff_proposal(
                    raw_retry, filepath, finding, code_content
                )
            if proposal is None:
                debug = (raw_retry or raw_text).strip()
                print("\n[DEBUG] Bob remediation response could not be parsed or salvaged:")
                print(debug[:4000] + ("..." if len(debug) > 4000 else ""))
                raise ValueError("Bob did not return a usable remediation proposal.")
        # The audit model may omit `snippet` even when it reports a valid line.
        # Derive the exact old text from the reported source line so patching does
        # not fail solely because the audit JSON was incomplete.
        old_snippet = str(finding.get("snippet") or "").strip()
        line_no = finding.get("line")
        if not old_snippet and isinstance(line_no, int) and 1 <= line_no <= len(code_content.splitlines()):
            old_snippet = code_content.splitlines()[line_no - 1].strip()

        proposal["target_file"] = str(filepath)
        proposal["vulnerability_id"] = proposal.get("vulnerability_id", finding.get("rule_id", "UNKNOWN"))
        proposal["severity"] = proposal.get("severity", finding.get("severity", "MEDIUM"))
        proposal["old_snippet"] = old_snippet
        proposal["line"] = line_no

        # Do not let an otherwise valid JSON object reach apply_patch() without
        # the fields required to perform a deterministic edit.
        replacement = str(proposal.get("replacement") or "").strip()
        if not old_snippet or not replacement:
            raise ValueError(
                "Bob returned an incomplete remediation proposal: "
                f"old_snippet={'present' if old_snippet else 'missing'}, "
                f"replacement={'present' if replacement else 'missing'}."
            )

        return proposal

    def backup_file(self, filepath: str) -> str:
        path = Path(filepath).resolve()
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

    @staticmethod
    def _normalize_replacement_indentation(
        replacement: str,
        reference_line: str,
    ) -> str:
        """
        Normalize LLM-generated multiline indentation relative to the target line.

        This prevents a common failure where Bob returns one extra leading space
        on the first line, producing invalid Python after patching.
        """
        base_indent = reference_line[: len(reference_line) - len(reference_line.lstrip())]

        lines = replacement.splitlines()
        non_empty = [
            line for line in lines
            if line.strip()
        ]

        if not non_empty:
            return replacement

        common_indent = min(
            len(line) - len(line.lstrip())
            for line in non_empty
        )

        normalized = []
        for line in lines:
            if not line.strip():
                normalized.append("")
            else:
                normalized.append(
                    base_indent + line[common_indent:]
                )

        result = "\n".join(normalized)
        if replacement.endswith("\n"):
            result += "\n"
        return result

    def apply_patch(self, proposal: Dict[str, Any]) -> Tuple[bool, str]:
        filepath = Path(str(proposal.get("target_file", ""))).resolve()
        old = str(proposal.get("old_snippet", ""))
        new = str(proposal.get("replacement", ""))

        if not filepath.is_file() or not old or not new:
            return False, "Patch proposal is incomplete or file missing."

        content = filepath.read_text(encoding="utf-8")
        if content.count(old) == 1:
            # Normalize indentation when an LLM returns a multiline replacement.
            first_line = next(
                (line for line in content.splitlines() if old.strip() in line),
                old,
            )
            safe_new = self._normalize_replacement_indentation(
                new,
                first_line,
            )
            filepath.write_text(content.replace(old, safe_new, 1), encoding="utf-8")
            return True, "Patch applied with normalized exact replacement."

        target_line = proposal.get("line")
        lines = content.splitlines(keepends=True)
        if isinstance(target_line, int) and 1 <= target_line <= len(lines):
            if lines[target_line - 1].strip() == old.strip():
                safe_new = self._normalize_replacement_indentation(
                    new,
                    lines[target_line - 1],
                )
                replacement_lines = safe_new.splitlines(keepends=True)
                if replacement_lines and not replacement_lines[-1].endswith("\n"):
                    replacement_lines[-1] += "\n"
                lines[target_line - 1 : target_line] = replacement_lines
                filepath.write_text("".join(lines), encoding="utf-8")
                return True, "Patch applied with exact line match."

        return False, "Target snippet could not be uniquely matched."

    def detect_test_command(self) -> Optional[List[str]]:
        root = self.project_root
        if (root / "package.json").is_file():
            return ["npm", "test"]
        if (root / "pytest.ini").is_file() or (root / "pyproject.toml").is_file() or list(root.glob("test_*.py")) or (root / "tests").is_dir():
            return [os.environ.get("PYTHON", "python"), "-m", "pytest", "-q"]
        return None

    def run_tests(self) -> Dict[str, Any]:
        command = self.detect_test_command()
        if not command:
            return {"status": "NOT_CONFIGURED", "passed": False, "command": None, "output": ""}

        def _run(env: Dict[str, str]) -> Dict[str, Any]:
            try:
                result = subprocess.run(
                    command,
                    cwd=self.project_root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=self.test_timeout,
                    check=False,
                )
                return {
                    "status": "PASS" if result.returncode == 0 else "FAIL",
                    "passed": result.returncode == 0,
                    "command": command,
                    "output": (result.stdout + "\n" + result.stderr).strip()[-4000:],
                }
            except Exception as exc:
                return {
                    "status": "ERROR",
                    "passed": False,
                    "command": command,
                    "output": str(exc),
                }

        env = os.environ.copy()
        result = _run(env)

        # Test-environment bootstrap: do not change application source. If test
        # collection fails specifically because SECRET_KEY is absent, rerun only
        # the test subprocess with an ephemeral test secret. This keeps a demo
        # hardcoded-secret finding meaningful while making the test harness usable.
        if (
            not result["passed"]
            and "KeyError: 'SECRET_KEY'" in result.get("output", "")
        ):
            test_env = env.copy()
            configured = os.getenv("BOBGUARD_TEST_SECRET_KEY")
            if configured:
                test_secret = configured
            else:
                test_secret = "bobguard-test-only-secret"
            test_env["SECRET_KEY"] = test_secret
            retry = _run(test_env)
            retry["environment_bootstrap"] = {
                "applied": True,
                "reason": "pytest collection required SECRET_KEY",
                "source": "BOBGUARD_TEST_SECRET_KEY" if configured else "ephemeral default",
            }
            return retry

        result["environment_bootstrap"] = {"applied": False}
        return result

    def validate_file_syntax(self, filepath: str) -> Dict[str, Any]:
        """
        Validasi syntax file yang baru dipatch.

        Untuk Python, py_compile menghasilkan detail file/baris/error pada stderr.
        Detail tersebut dikembalikan ke CLI agar penyebab PATCH FAILED terlihat.
        """
        path = Path(filepath).resolve()
        command: Optional[List[str]] = None

        if path.suffix.lower() == ".py":
            command = [
                os.environ.get("PYTHON", "python"),
                "-m",
                "py_compile",
                str(path),
            ]
        elif path.suffix.lower() == ".js":
            command = ["node", "--check", str(path)]

        if not command:
            return {
                "status": "NOT_AVAILABLE",
                "passed": True,
                "command": None,
                "output": "",
                "traceback": "",
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

            combined_output = (
                (result.stdout or "") + "\n" + (result.stderr or "")
            ).strip()

            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "passed": result.returncode == 0,
                "command": command,
                "output": combined_output,
                "traceback": "",
            }

        except subprocess.TimeoutExpired as exc:
            tb = traceback.format_exc()
            return {
                "status": "TIMEOUT",
                "passed": False,
                "command": command,
                "output": str(exc),
                "traceback": tb,
            }

        except Exception as exc:
            return {
                "status": "ERROR",
                "passed": False,
                "command": command,
                "output": str(exc),
                "traceback": traceback.format_exc(),
            }

    def verify_finding_resolved(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        try:
            findings = self.audit_file_with_bob_llm(
                str(finding.get("file", "")),
                focus_finding=finding,
            )
        except Exception as exc:
            return {
                "passed": False,
                "status": "ERROR",
                "remaining_findings": [],
                "error": str(exc),
            }

        same_rule = [
            f for f in findings
            if str(f.get("rule_id", "")) == str(finding.get("rule_id", ""))
            or str(finding.get("name", "")).lower() in str(f.get("name", "")).lower()
        ]
        return {
            "passed": len(same_rule) == 0,
            "status": "PASS" if len(same_rule) == 0 else "FAIL",
            "remaining_findings": same_rule,
        }

    @staticmethod
    def _print_patch_failure_details(
        reason: str,
        baseline: Dict[str, Any],
        changed_paths: List[str],
        attempt: int,
    ) -> None:
        print(f"\n[DEBUG] Remediation verification attempt {attempt}: {reason}")
        if changed_paths:
            print("[DEBUG] Changed files:")
            for path in changed_paths:
                print(f"  - {path}")
        baseline_output = baseline.get("output", "")
        if baseline_output:
            failures = BobGuardBackend._extract_test_failure_ids(baseline_output)
            if failures:
                print("[DEBUG] Baseline failing tests:")
                for failure in sorted(failures):
                    print(f"  - {failure}")

    def remediate_and_verify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        target_path = Path(str(finding.get("file", ""))).resolve()
        if is_test_file(target_path, self.project_root):
            return {
                "status": "NOT_REMEDIATED",
                "reason": "Test files are verification evidence and are not remediation targets.",
                "file": str(target_path),
            }

        workspace_before = self._snapshot_workspace()
        target_file = str(target_path)
        baseline = self.run_tests()

        proposal = None
        changed_paths = []
        retry_reason = ""
        max_attempts = 2

        for attempt in range(1, max_attempts + 1):
            # Restore the exact pre-attempt workspace before every retry.
            self._restore_workspace(workspace_before)
            try:
                proposal = self._agent_edit_file(finding, retry_reason=retry_reason)
            except Exception as exc:
                self._restore_workspace(workspace_before)
                self._print_patch_failure_details(
                    reason=str(exc),
                    baseline=baseline,
                    changed_paths=[],
                    attempt=attempt,
                )
                return {
                    "status": "PATCH_NOT_APPLIED",
                    "error": str(exc),
                    "baseline": baseline,
                    "attempt": attempt,
                }

            workspace_after = self._snapshot_workspace()
            changed_paths = self._changed_paths(workspace_before, workspace_after)
            allowed_path = str(target_path)
            unexpected_changes = [p for p in changed_paths if p != allowed_path]

            if allowed_path in changed_paths and not unexpected_changes:
                break

            if unexpected_changes and attempt < max_attempts:
                retry_reason = (
                    "The previous attempt modified unauthorized files: "
                    + ", ".join(unexpected_changes)
                    + ". Revert that behavior and edit ONLY the target file."
                )
                self._print_patch_failure_details(
                    reason="Agent modified files outside the authorized target; retrying once.",
                    baseline=baseline,
                    changed_paths=changed_paths,
                    attempt=attempt,
                )
                continue

            self._restore_workspace(workspace_before)
            reason = (
                "Agent modified files outside the authorized target."
                if unexpected_changes
                else "Agent completed without changing the authorized target file."
            )
            self._print_patch_failure_details(
                reason=reason,
                baseline=baseline,
                changed_paths=changed_paths,
                attempt=attempt,
            )
            return {
                "status": "PATCH FAILED / ROLLED BACK" if unexpected_changes else "PATCH_NOT_APPLIED",
                "reason": reason,
                "changed_paths": changed_paths,
                "baseline": baseline,
                "attempt": attempt,
            }

        syntax = self.validate_file_syntax(target_file)
        tests = self.run_tests()
        regression = self._test_regression(baseline, tests)
        security = self.verify_finding_resolved(finding)

        verification = {
            "target_fixed": security["passed"],
            "syntax_passed": syntax["passed"],
            "no_new_regressions": regression["passed"],
            "full_suite_green": tests["passed"],
            "test_environment_bootstrapped": bool(
                tests.get("environment_bootstrap", {}).get("applied")
            ),
            "preexisting_failures_remaining": bool(regression["post_failures"]),
            "remaining_preexisting_failures": regression["post_failures"],
        }

        # For intentionally vulnerable training/demo applications, pre-existing
        # security-test failures are allowed to remain. What must not happen is a
        # new regression, a syntax break, or persistence of the target finding.
        verification_passed = (
            syntax["passed"]
            and regression["passed"]
            and security["passed"]
        )

        if verification_passed:
            final_status = (
                "FIXED & VERIFIED"
                if tests["passed"]
                else "FIXED & VERIFIED — OTHER FINDINGS REMAIN"
            )
            print(
                "\n[DEBUG] Verification: target_fixed=%s, syntax=%s, new_regressions=%s, full_suite_green=%s"
                % (security["passed"], syntax["passed"], not regression["passed"], tests["passed"])
            )
            return {
                "status": final_status,
                "proposal": proposal,
                "baseline": baseline,
                "syntax": syntax,
                "tests": tests,
                "regression": regression,
                "security_rescan": security,
                "changed_paths": changed_paths,
                "verification": verification,
            }

        self._print_patch_failure_details(
            reason=(
                f"Verification failed: syntax={syntax["passed"]}, "
                f"no_new_regressions={regression["passed"]}, "
                f"target_fixed={security["passed"]}"
            ),
            baseline=baseline,
            changed_paths=changed_paths,
            attempt=1,
        )
        self._restore_workspace(workspace_before)
        return {
            "status": "PATCH FAILED / ROLLED BACK",
            "proposal": proposal,
            "baseline": baseline,
            "syntax": syntax,
            "tests": tests,
            "regression": regression,
            "security_rescan": security,
            "changed_paths": changed_paths,
            "verification": verification,
        }
