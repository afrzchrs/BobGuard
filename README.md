
# BobGuard: Autonomous DevSecOps Orchestrator for IBM Bob 2.0

BobGuard is an autonomous security engineering agent and interactive CLI tool powered by **IBM Bob 2.0** and **IBM Granite**. It continuously audits codebases against **OWASP Top 10** standards, generates evidence-backed triage reports, proposes atomic unified diffs, and safely applies verified security patches with mandatory **Human-in-the-Loop (HITL)** approval and automatic rollbacks.

---

## Key Features

* **Single Source of Truth (SSOT) Architecture:** Audit policies and patch strategies are strictly defined in declarative Markdown documents (`.bob/rules/` and `.bob/prompts/`), consumed identically by the CLI and IBM Bob IDE Agent Mode.
* **Zero False-Positive Semantic Triage:** Leverages IBM Bob 2.0's LLM engine to perform full data-flow and taint analysis rather than brittle static regex.
* **Fail-Safe Remediation Transaction:** Every automated patch follows a deterministic pipeline:

$$
\text{Backup} \longrightarrow \text{Atomic Patch} \longrightarrow \text{Syntax Validation} \longrightarrow \text{Regression Tests} \longrightarrow \text{LLM Re-scan} \longrightarrow \text{Commit / Rollback}
$$

If test suites fail or syntax errors occur, BobGuard restores the exact original file automatically.

* **Human-in-the-Loop (HITL) Governance:** No file on the local filesystem is modified without explicit interactive developer authorization (`Y/n`).
* **Pre-Flight Workspace Guard:** Detects empty target repositories upfront and guides developers to mount code before expending inference credits.
* **Polyglot & Framework Agnostic:** Centralized extension routing (`supported_extension.py`) covering Frontend, Backend, Templates, and Configurations.

---

## System Architecture

```text
                                 Developer Terminal
                                         │
                                         ▼
                                  $ bobguard run
                                         │
                       ┌─────────────────┴─────────────────┐
                       │   CLI Frontend (cli.py / Rich)    │
                       └─────────────────┬─────────────────┘
                                         │
                        [Early Guard: Workspace Check] ──► (Empty? Halt & Guide)
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │   Backend Engine (bobguard_backend)   │
                     └───────────────────┬───────────────────┘
                                         │
             ┌───────────────────────────┼───────────────────────────┐
             ▼                           ▼                           ▼
   .bob/rules/owasp-*.md       .bob/prompts/audit-*.md    .bob/prompts/patch-*.md
   (OWASP Knowledge Base)      (Orchestrator Protocol)    (Remediation Guardrails)
             │                           │                           │
             └───────────────────────────┼───────────────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │   IBM Bob 2.0 / Granite LLM     │
                        │    (REST API / Bob Shell)       │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │   Triage Report Table (Rich)    │
                        │  Severity | Category | Snippet  │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │  Unified Diff Proposal Preview  │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ Human-in-the-Loop Prompt (Y/n)  │
                        └────────────────┬────────────────┘
                                         │ (Approved 'Y')
                                         ▼
                     ┌───────────────────────────────────────┐
                     │     Safe Verification Pipeline        │
                     │  1. Create Temporary .bak File        │
                     │  2. Apply Atomic Replacement          │
                     │  3. Syntax Validation (Node/Python)   │
                     │  4. Run Regression Test Suite         │
                     │  5. Targeted LLM Security Re-Scan     │
                     └───────────────────┬───────────────────┘
                                         │
                       ┌─────────────────┴─────────────────┐
                 (All Passed)                         (Any Failed)
                       ▼                                   ▼
             [✓ FIXED & VERIFIED]                [✗ AUTOMATIC ROLLBACK]
             (Cleanup backup)                    (Restore original file)

```

---

## Repository Structure

```text
├── .bob/
│   ├── rules/
│   │   └── owasp-top10-guide-2025.md      # Grounded OWASP compliance rules
│   └── prompts/
│       ├── audit-orchestrator-2025.md    # Multi-domain audit workflow instructions
│       └── patch-remediation-2025.md     # Safe remediation & unified diff protocol
├── sample-app/
│   ├── app.py                            # Target application with deliberate flaws
│   ├── test_app.py                       # Automated test suite for regression verification
│   └── requirements.txt                  # Minimal application dependencies
├── bobguard_backend.py                   # Core orchestration, LLM interface & rollback engine
├── cli.py                                # Visual terminal UI with Rich & ASCII banners
├── supported_extension.py                # Supported file extension registry
├── bobguard.bat                          # Windows CLI wrapper
├── install.sh                            # Linux / macOS CLI installer
├── .env.example                          # Environment variable configuration template
├── .gitignore
├── .bobignore
└── README.md

```

---

## Quickstart Guide

### 1. Prerequisites

* Python 3.9+ installed
* An active IBM Bob 2.0 account and API Key from [bob.ibm.com](https://bob.ibm.com?utm_source=gemini)

### 2. Installation & Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/<your-username>/BobGuard.git
cd BobGuard

# Install core CLI dependencies
pip install rich requests python-dotenv pytest

```

Configure your environment variables:

```bash
# Copy example environment configuration
cp .env.example .env

```

Open `.env` and fill in your credentials:

```env
BOB_API_KEY=your_actual_ibm_bob_api_key_here
BOB_API_ENDPOINT=https://api.bob.ibm.com/v1/chat/completions
BOB_MODEL=ibm-granite
BOB_REQUEST_TIMEOUT=90
BOBGUARD_TEST_TIMEOUT=120

```

---

### 3. Setting Up Global CLI Command

#### On Windows (PowerShell / CMD)

Add the current directory to your user PATH or use the batch wrapper:

```powershell
# Method A: Current session shortcut
function bobguard { python "$PWD\cli.py" $args }

# Method B: Direct call via batch file
.\bobguard run

```

#### On Linux / macOS / WSL

Make the launcher executable and link it to your binary path:

```bash
chmod +x cli.py
sudo ln -sf "$(pwd)/cli.py" /usr/local/bin/bobguard

# Verify installation
bobguard --help

```

---

## Usage

### 1. Full Audit and Interactive Remediation Pipeline

Performs environment discovery, analyzes all source code via IBM Bob 2.0, presents findings, and guides you through patching:

```bash
bobguard run
# Or target a specific workspace
bobguard run --dir sample-app

```

### 2. Read-Only Security Assessment

Runs the triage engine and prints the findings table without prompting for file mutations:

```bash
bobguard scan
# Or target a specific workspace
bobguard scan --dir sample-app

```

---

## Demonstration with `sample-app`

The repository includes a ready-to-test workspace in `sample-app/`:

1. **Verify Early Guard Check:**
   Remove files in `sample-app/` to observe the workspace guard in action:

```bash
bobguard run --dir sample-app

```

*Output:*

```text
╭───────────────────────── Empty Target Workspace ─────────────────────────╮
│ Workspace directory 'sample-app' is empty or contains no supported code!   │
│                                                                            │
│ copy or pull your code to sample-app to let Bob do his audit job        │
╰────────────────────────────────────────────────────────────────────────────╯
```

2. **Execute Audit & Verified Remediation:**
   Ensure `sample-app/app.py` and `sample-app/test_app.py` are in place, then execute:

```bash
bobguard run --dir sample-app

```

* Watch BobGuard identify the SQL Injection and Hardcoded Secret.
* Inspect the proposed Unified Diff generated by IBM Bob.
* Press `Y` to authorize the patch.
* Observe automated syntax verification, `pytest` regression execution, and targeted security re-scans confirm `✓ FIXED & VERIFIED`.

3. **Resetting the Demo:**
   Restore the vulnerable file state to repeat the test:

```powershell
# Windows PowerShell
Copy-Item sample-app\app.py.bak sample-app\app.py -Force

# Linux / macOS
cp sample-app/app.py.bak sample-app/app.py

```

---

## Security & Governance

* **Zero Credential Leakage:** API keys are restricted to local `.env` files protected by `.gitignore` and `.bobignore`.
* **Atomic Operations:** Code replacements occur as single-occurrence substitutions or strict line matches to prevent unintended file alterations.
* **Deterministic Rollback:** If any post-patch check fails (syntax compilation, unit test regression, or residual vulnerability detection), the temporary `.bak` file is restored immediately, leaving the working directory clean.
