# agent-identity-guard

A lightweight security CLI that audits a repository for **agent/bot identity risk**
and **CI supply-chain tampering**. It looks in two places:

1. **Workflow definitions** (`src/agent_guard/scanner.py`) — parses
   `.github/workflows/*.yml` with PyYAML and applies least-privilege checks.
2. **Git history** (`src/agent_guard/agent_audit.py`) — uses GitPython to find
   automated identities that rewrote pipeline files.

## Install

```bash
uv sync
```

## Usage

```bash
agent-identity-guard audit --path <repo_path>
```

`--path` defaults to the current directory. The summary table is color-coded
(CRITICAL red, HIGH yellow). The command exits with status `1` when at least one
CRITICAL finding is reported, so it can gate a pipeline; `0` otherwise.

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
