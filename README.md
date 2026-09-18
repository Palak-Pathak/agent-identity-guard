# SDLC Security Engine for Non-Human Identities & AI Agent CI/CD Auditing

A lightweight security CLI that audits a repository for **agent/bot identity risk** and **CI supply-chain tampering**. It inspects two surfaces:

1. **Workflow definitions** (`src/agent_guard/scanner.py`) — parses `.github/workflows/*.yml` with PyYAML and applies least-privilege checks.
2. **Git history** (`src/agent_guard/agent_audit.py`) — uses GitPython to detect automated identities altering pipeline configurations.

---

## ⚡ Features

* **Ambient Token Over-Privilege Detection:** 
  * Identifies workflows missing explicit top-level `permissions` definitions (defaulting to broad read/write tokens).
  * Flags dangerous `permissions: write-all` declarations at both global and job-level scopes.
* **Poisoned Pipeline Protection:** 
  * Flags high-risk triggers like `pull_request_target` that can expose repository secrets to untrusted forks.
* **Non-Human Identity (NHI) Behavioral Auditing:** 
  * Scans Git commit history to detect automated agents and service bots (`[bot]`, `github-actions`, `copilot`, `cursor`, `dependabot`, etc.).
  * Catches unauthorized pipeline tampering where an automated identity modifies files inside `.github/workflows/`.
* **Edge-Case Parsing & Resilience:**
  * Handles YAML 1.1 boolean parsing quirks (where `on:` parses natively as boolean `True`).
  * Coerces dynamic Git actor signatures safely to prevent runtime type exceptions.
  * Formatted output using `rich` with color-coded severity tables and explicit rule-reference legends.

---

## 🚀 Quickstart & Usage

Ensure you have [uv](https://github.com/astral-sh/uv) installed.

```bash
# Clone & install dependencies
git clone [https://github.com/Palak-Pathak/agent-identity-guard.git](https://github.com/Palak-Pathak/agent-identity-guard.git)
cd agent-identity-guard
uv sync

# Run audit on target repository
uv run agent-identity-guard audit --path <repo_path>

## Rules

| ID | Severity | Detects |
| --- | --- | --- |
| `AG-WF-001` | HIGH | Missing top-level `permissions` block |
| `AG-WF-002` | CRITICAL | `permissions: write-all` (every token scope) |
| `AG-WF-003` | CRITICAL | `pull_request_target` trigger (supply-chain poisoning vector) |
| `AG-WF-004` | MEDIUM | Workflow is not valid YAML |
| `AG-WF-005` | MEDIUM | Workflow document root is not a mapping |
| `AG-WF-006` | MEDIUM | Workflow file could not be read |
| `AG-AGENT-001` | CRITICAL | Bot/agent commit modifies files in `.github/workflows/` |

Bot identities are matched against a regex set including `[bot]`,
`github-actions`, `copilot`, `cursor`, and `dependabot`, over the last 50
commits.

## Development

```bash
uv run pytest          # unit tests
uv run mypy src        # type check
uv run --with ruff ruff check src tests
```
