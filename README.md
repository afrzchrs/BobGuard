
# BobGuard: Autonomous DevSecOps Orchestrator for IBM Bob 2.0

BobGuard is an autonomous security engineering agent and interactive CLI tool powered by **IBM Bob 2.0** and **IBM Granite**. It continuously audits codebases against **OWASP Top 10** standards, generates evidence-backed triage reports, proposes atomic unified diffs, and safely applies verified security patches with mandatory **Human-in-the-Loop (HITL)** approval and automatic rollbacks.

---

## Key Features

* **Single Source of Truth (SSOT) Architecture:** Audit policies and patch strategies are strictly defined in declarative Markdown documents (`.bob/rules/` and `.bob/prompts/`), consumed identically by the CLI and IBM Bob IDE Agent Mode.
* **Zero False-Positive Semantic Triage:** Leverages IBM Bob 2.0's LLM engine via Bob Shell to perform full semantic taint analysis rather than brittle static regex.
* **Fail-Safe Remediation Transaction:** Every automated patch follows a deterministic pipeline:

$$
\text{Backup} \longrightarrow \text{Atomic Patch} \longrightarrow \text{Syntax Validation} \longrightarrow \text{Regression Tests} \longrightarrow \text{LLM Re-scan} \longrightarrow \text{Commit / Rollback}
$$

If test suites fail or syntax errors occur, BobGuard restores the exact original file automatically.

* **Human-in-the-Loop (HITL) Governance:** No file on the local filesystem is modified without explicit interactive developer authorization (`y/N`).
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
                        │   IBM Bob 2.0 Shell (Headless)  │
                        │   bob run --format json         │
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

## IBM Bob 2.0 Environment & Toolchain Setup

BobGuard operates seamlessly alongside IBM Bob IDE for local development and automates audits through the headless IBM Bob Shell (`bob` CLI).

### 1. Setting Up IBM Bob IDE

1. **Install Extension / IDE:** In VS Code or your Bob IDE distribution, navigate to the Extensions tab (`Ctrl+Shift+X` or `Cmd+Shift+X`), search for **IBM Bob**, and install it.
2. **Authenticate:** Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`), run `IBM Bob: Sign In`, and complete authentication via your browser from [bob.ibm.com](https://bob.ibm.com?utm_source=gemini).
3. **Workspace Context Activation:** When this repository is opened in IBM Bob IDE, the agent automatically recognizes the `.bob/` convention:

* `.bob/rules/`: OWASP Top 10 rules loaded into active context for developer queries.
* `.bob/prompts/`: Audit and patch orchestration instructions ensuring consistent findings between IDE chats and CLI audits.

---

### 2. Installing & Verifying IBM Bob Shell (`bob` CLI)

BobGuard executes scans non-interactively using the official `bob` command-line utility.

1. **Verify Existing Installation:**
   Check if the binary is already available in your system path:

```bash
bob --version

```

2. **Install Standalone CLI (if not installed):**

```bash
npm install -g @ibm/bob-cli

```

Ensure the directory containing `bob` (or `bob.cmd` on Windows) is registered in your system `PATH`.

---

### 3. Environment Variable Configuration Methods

BobGuard supports three complementary methods to supply configuration parameters (such as `BOB_API_KEY`, timeout thresholds, and execution cost limits):

#### Method A: Via Local `.env` File (Recommended)

Copy the template and supply your production key:

```bash
cp .env.example .env

```

Fill in the parameters in `.env`:

```env
# Required: IBM Bob API Key (starts with bob_prod...)
BOB_API_KEY=bob_prod_your_api_key_here
```

`BobGuardBackend` uses `python-dotenv` to automatically load this configuration upon startup.

#### Method B: Via System / Shell Environment Variables

If you prefer not to store credentials in a local file, set the variable directly in your operating system:

* **Windows (PowerShell - Current Session):**

```powershell
$env:BOB_API_KEY = "bob_prod_your_api_key_here"

```

* **Windows (Persistent for User Profile):**

```powershell
[Environment]::SetEnvironmentVariable("BOB_API_KEY", "bob_prod_your_api_key_here", [EnvironmentVariableTarget]::User)

```

* **Linux / macOS (Bash / Zsh):**

```bash
export BOB_API_KEY="bob_prod_your_api_key_here"
echo 'export BOB_API_KEY="bob_prod_your_api_key_here"' >> ~/.bashrc

```

#### Method C: Programmatic Setup Directly in Python

Because `bobguard_backend.py` respects existing variables without overriding them (`override=False`), you can configure credentials dynamically from custom scripts or Jupyter notebooks before initializing the backend:

```python
import os
from bobguard_backend import BobGuardBackend

# Set environment programmatically
os.environ["BOB_API_KEY"] = "bob_prod_your_api_key_here"
os.environ["BOB_REQUEST_TIMEOUT"] = "120"
os.environ["BOB_MAX_COST"] = "0.50"

# Initialize and scan target codebase
backend = BobGuardBackend(project_root="sample-app")
findings = backend.scan_entire_codebase("sample-app")
print(f"Discovered {len(findings)} security findings.")

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
│   ├── db.py                             # Database operations
│   ├── tests/                            # Automated test suite for regression verification
│   └── requirements.txt                  # Application dependencies
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

* Python 3.9+
* Node.js & npm (if using the Bob CLI npm package)
* IBM Bob CLI (`bob`) accessible from your terminal
* An active IBM Bob account with API access

### 2. Installation & Dependency Setup

Clone the repository and install the required Python packages:

```bash
git clone https://github.com/<your-username>/BobGuard.git
cd BobGuard

# Install core CLI and testing dependencies
pip install rich requests python-dotenv pytest

```

Configure your environment:

```bash
cp .env.example .env
# Edit .env and supply your BOB_API_KEY

```

---

### 3. Setting Up Global CLI Access

#### On Windows (PowerShell / CMD)

Run through the included batch script:

```powershell
.\bobguard run

```

Or define an alias for your current terminal session:

```powershell
function bobguard { python "$PWD\cli.py" $args }

```

#### On Linux / macOS / WSL

Make the Python CLI executable and link it to your binary directory:

```bash
chmod +x cli.py
sudo ln -sf "$(pwd)/cli.py" /usr/local/bin/bobguard

# Verify installation
bobguard --help

```

---

## Usage

### 1. Full Audit and Interactive Remediation Pipeline (`run`)

Discovers files, analyzes them against OWASP rules, displays findings, prompts for approval, and applies safe verified fixes:

```bash
bobguard run
# Or target a specific workspace directory
bobguard run --dir sample-app

```

### 2. Read-Only Security Assessment (`scan`)

Runs the triage engine and prints the findings table without modifying files or generating patches:

```bash
bobguard scan
# Or target a specific workspace directory
bobguard scan --dir sample-app

```

---

## Demonstration with `sample-app`

The repository includes a vulnerable web application under `sample-app/` for testing and evaluation.

### 1. Verify Pre-Flight Workspace Guard

Point BobGuard to an empty or non-code folder:

```bash
bobguard run 
```

*Expected Terminal Output:*

```text
╭─────────────────────────   Empty Target Workspace ─────────────────────────╮
│ Workspace directory 'docs' is empty or contains no supported code!         │
│                                                                            │
│     copy or pull your code to docs to let Bob do his audit job             │
╰────────────────────────────────────────────────────────────────────────────╯
```

### 2. Execute Full Audit & Safe Patch Verification

Run BobGuard against the sample app:

```bash
./bobguard run 
```

1. **Semantic Discovery:** BobGuard identifies active issues (e.g., SQL Injection and Hardcoded Secrets) and displays an OWASP triage table.
2. **Unified Diff Inspection:** A colorized diff preview shows the proposed changes.
3. **HITL Authorization:** Approve the patch when prompted (`y`).
4. **Verification Transaction:** BobGuard compiles the patched file, runs the `pytest` regression suite, and performs an LLM security re-scan before confirming `✓ FIXED & VERIFIED`.

### 3. Resetting the Demo for Repeated Runs

To reset the demonstration app back to its initial vulnerable state:

* **Windows PowerShell:**

```powershell
Copy-Item sample-app\app.py.bak sample-app\app.py -Force

```

* **Linux / macOS:**

```bash
cp sample-app/app.py.bak sample-app/app.py

```

---

## Security & Governance

* **Zero Credential Leakage:** API keys are restricted to local environment files protected by `.gitignore` and `.bobignore`.
* **Atomic Patch Application:** Code replacements occur as single-occurrence substitutions or strict line matches to prevent unintended file alterations.
* **Deterministic Rollback:** If any post-patch check fails (syntax compilation, unit test regression, or residual vulnerability detection), the temporary `.bak` file is restored immediately, leaving the working directory clean.
