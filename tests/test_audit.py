"""Unit tests for the workflow scanner and the git history agent audit."""

from __future__ import annotations

from pathlib import Path

from git import Actor, Repo

from agent_guard.agent_audit import audit_agent_commits, detect_agent
from agent_guard.models import Severity
from agent_guard.scanner import scan_workflows

WORKFLOW_DIR = Path(".github") / "workflows"


def _write_workflow(root: Path, name: str, content: str) -> Path:
    workflow_dir = root / WORKFLOW_DIR
    workflow_dir.mkdir(parents=True, exist_ok=True)
    path = workflow_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def test_scan_workflows_flags_permissions_and_pull_request_target(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "unsafe.yml",
        """
name: unsafe
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "untrusted"
""",
    )
    _write_workflow(
        tmp_path,
        "no-permissions.yml",
        """
name: no-permissions
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ok"
""",
    )

    findings = scan_workflows(tmp_path)
    by_file: dict[str, set[str]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, set()).add(finding.rule.id)

    assert by_file[".github/workflows/unsafe.yml"] == {"AG-WF-002", "AG-WF-003"}
    assert by_file[".github/workflows/no-permissions.yml"] == {"AG-WF-001"}

    write_all = next(f for f in findings if f.rule.id == "AG-WF-002")
    target = next(f for f in findings if f.rule.id == "AG-WF-003")
    missing = next(f for f in findings if f.rule.id == "AG-WF-001")
    assert write_all.severity is Severity.CRITICAL
    assert target.severity is Severity.CRITICAL
    assert missing.severity is Severity.HIGH


def test_scan_workflows_survives_malformed_yaml(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "broken.yml", "name: broken\non: [push\npermissions: {}\n")

    findings = scan_workflows(tmp_path)

    assert len(findings) == 1
    assert findings[0].rule.id == "AG-WF-004"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].line is not None


def test_audit_agent_commits_flags_bot_workflow_tampering(tmp_path: Path) -> None:
    repo = Repo.init(tmp_path)
    _write_workflow(
        tmp_path,
        "release.yml",
        """
name: release
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ok"
""",
    )

    bot = Actor("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")
    repo.index.add([str(WORKFLOW_DIR / "release.yml")])
    repo.index.commit("chore: bump action version", author=bot, committer=bot)

    # A human then edits the same workflow; this must not be reported.
    human = Actor("Jane Dev", "jane@example.com")
    workflow_path = tmp_path / WORKFLOW_DIR / "release.yml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8") + "# reviewed by a human\n",
        encoding="utf-8",
    )
    repo.index.add([str(WORKFLOW_DIR / "release.yml")])
    repo.index.commit("ci: review release workflow", author=human, committer=human)

    findings = audit_agent_commits(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule.id == "AG-AGENT-001"
    assert finding.severity is Severity.CRITICAL
    assert finding.file == ".github/workflows/release.yml"
    assert "dependabot" in finding.message
    assert "dependabot[bot]" in finding.message

    assert detect_agent("Jane Dev <jane@example.com>") is None
    assert detect_agent("github-actions[bot] <actions@github.com>") == "github-actions"
