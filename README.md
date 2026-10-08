# AutoSec-Patch: Autonomous CVE Remediation & Regression Agent

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Nebius AI Cloud](https://img.shields.io/badge/Powered%20By-Nebius%20Token%20Factory-purple)](https://nebius.ai)
[![NVIDIA Model](https://img.shields.io/badge/Model-NVIDIA%20Nemotron-green)](https://developer.nvidia.com)

**Track:** Coding and Agent Engineering Track (Nebius x NVIDIA Global AI Hackathon)

**AutoSec-Patch** is an autonomous security remediation agent powered by **NVIDIA Nemotron** via **Nebius Token Factory**. It parses static analysis findings (SARIF / SAST JSON), reasons over security vulnerabilities (e.g., SQL Injection, Path Traversal, Command Injection), synthesizes minimal production-ready patches following the YAGNI principle, and verifies them against automated regression test suites with a self-healing loop.

---

## Key Features

1. **Native SARIF v2.1.0 & SAST Parsing**: Supports standard vulnerability reports from Semgrep, Bandit, Snyk, and GitHub Code Scanning.
2. **NVIDIA Nemotron Reasoning via Nebius Token Factory**: Leverages state-of-the-art open models (`nvidia/llama-3.1-nemotron-70b-instruct` / Nemotron Ultra) for precise vulnerability remediation without breaking business logic.
3. **Automated Sandbox Verification & Self-Healing**: Automatically applies unified diffs and executes test suites. If regressions occur, AutoSec triggers a targeted feedback loop to heal the patch.
4. **Zero Overhead / YAGNI Design**: Produces clean, readable, standard Git unified diffs.

---

## Architecture & Workflow

```
[ SAST Findings (SARIF) ] ──> [ Parser ] ──> [ Nebius Nemotron Engine ]
                                                     │
                                             (Unified Diff Patch)
                                                     ▼
                                            [ Apply Patch to Repo ]
                                                     │
                                            [ Run Regression Tests ]
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             ▼                                               ▼
                         [ PASS ]                                         [ FAIL ]
                    (Remediation Complete)                         (Self-Healing Loop)
```

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/<your-username>/autosec-patch.git
cd autosec-patch
pip install -e .
```

### 2. Configure Environment

Set your Nebius Token Factory credentials:

```bash
export NEBIUS_API_KEY="your-nebius-token-factory-api-key"
export NEBIUS_BASE_URL="https://api.studio.nebius.ai/v1"
export NEBIUS_MODEL="nvidia/llama-3.1-nemotron-70b-instruct"
```

### 3. Run Autonomous Remediation

```bash
python3 -m autosec.cli remediate \
  --sarif examples/sample_sarif.json \
  --repo . \
  --test-cmd "python3 -m unittest examples/test_vulnerable.py"
```

---

## Verification & Testing

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

---

## License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.
