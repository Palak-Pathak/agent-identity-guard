"""Static analysis of GitHub Actions workflow definitions.

Each ``.github/workflows/*.yml`` file is parsed with PyYAML and checked against a
small set of high-signal supply-chain rules. Malformed input never raises out of
:func:`scan_workflows`; instead it is reported as a MEDIUM finding so a broken
workflow cannot silently hide the checks below it.

Note:
    PyYAML implements YAML 1.1, where the bare key ``on:`` deserialises to the
    boolean ``True`` rather than the string ``"on"``. Trigger lookups therefore
    accept both spellings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .errors import WorkflowScanError
from .models import Finding, Rule, Severity

__all__ = [
    "RULE_INVALID_STRUCTURE",
    "RULE_MALFORMED_YAML",
    "RULE_MISSING_PERMISSIONS",
    "RULE_PULL_REQUEST_TARGET",
    "RULE_UNREADABLE_WORKFLOW",
    "RULE_WRITE_ALL_PERMISSIONS",
    "scan_workflow_file",
    "scan_workflows",
    "workflow_files",
]

WORKFLOWS_DIR = Path(".github") / "workflows"
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
CATEGORY = "workflow"


RULE_MISSING_PERMISSIONS = Rule(
    id="AG-WF-001",
    title="Missing top-level permissions block",
    severity=Severity.HIGH,
    description=(
        "The workflow declares no top-level 'permissions' block, so every job "
        "inherits the repository default token scope. Declare least-privilege "
        "permissions explicitly to bound the blast radius of a compromised step."
    ),
)

RULE_WRITE_ALL_PERMISSIONS = Rule(
    id="AG-WF-002",
    title="'permissions: write-all' grants every token scope",
    severity=Severity.CRITICAL,
    description=(
        "The workflow requests write access to every available token scope. Any "
        "compromised or untrusted step inherits those privileges and can push "
        "commits, publish releases, or rewrite workflows."
    ),
)

RULE_PULL_REQUEST_TARGET = Rule(
    id="AG-WF-003",
    title="Trigger 'pull_request_target' runs with elevated context",
    severity=Severity.CRITICAL,
    description=(
        "'pull_request_target' executes against the base repository with its "
        "token and secrets, even for fork pull requests. When combined with a "
        "checkout of untrusted head code this is the classic supply-chain "
        "poisoning vector."
    ),
)

RULE_MALFORMED_YAML = Rule(
    id="AG-WF-004",
    title="Workflow file is not valid YAML",
    severity=Severity.MEDIUM,
    description=(
        "The workflow could not be parsed, so its permissions and triggers could "
        "not be verified. Fix the syntax and re-run the audit."
    ),
)

RULE_INVALID_STRUCTURE = Rule(
    id="AG-WF-005",
    title="Workflow document root is not a mapping",
    severity=Severity.MEDIUM,
    description=(
        "A GitHub Actions workflow must be a YAML mapping at the document root. "
        "The file was skipped because its structure is not auditable."
    ),
)

RULE_UNREADABLE_WORKFLOW = Rule(
    id="AG-WF-006",
    title="Workflow file could not be read",
    severity=Severity.MEDIUM,
    description=(
        "The workflow file could not be read as UTF-8 text and was skipped. "
        "Check file permissions and encoding."
    ),
)


def workflow_files(repo_path: Path | str) -> list[Path]:
    """Return the auditable workflow files under *repo_path*, sorted by name."""
    workflows_dir = Path(repo_path) / WORKFLOWS_DIR
    if not workflows_dir.is_dir():
        return []
    return sorted(
        path
        for path in workflows_dir.iterdir()
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def scan_workflow_file(path: Path, repo_root: Path) -> list[Finding]:
    """Audit a single workflow file, returning every finding it triggers."""
    relative = _relative_path(path, repo_root)

    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [
            Finding.from_rule(
                RULE_UNREADABLE_WORKFLOW,
                file=relative,
                message=f"Could not read workflow: {exc}",
                category=CATEGORY,
            )
        ]

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        first_line, line_number = _yaml_problem(exc)
        return [
            Finding.from_rule(
                RULE_MALFORMED_YAML,
                file=relative,
                message=f"Could not parse YAML at line {line_number}: {first_line}",
                category=CATEGORY,
                line=line_number,
            )
        ]

    if document is None:
        return [
            Finding.from_rule(
                RULE_INVALID_STRUCTURE,
                file=relative,
                message="Workflow file is empty.",
                category=CATEGORY,
            )
        ]

    if not isinstance(document, dict):
        return [
            Finding.from_rule(
                RULE_INVALID_STRUCTURE,
                file=relative,
                message=(
                    "Expected a mapping at the document root, found "
                    f"{type(document).__name__}."
                ),
                category=CATEGORY,
            )
        ]

    return _check_workflow(document, relative)


def scan_workflows(repo_path: Path | str) -> list[Finding]:
    """Audit every workflow under ``<repo_path>/.github/workflows``.

    Raises:
        WorkflowScanError: if *repo_path* is not an existing directory.
    """
    root = Path(repo_path)
    if not root.is_dir():
        raise WorkflowScanError(f"Not a directory: {root}")

    findings: list[Finding] = []
    for path in workflow_files(root):
        findings.extend(scan_workflow_file(path, root))
    return findings


def _check_workflow(document: dict[Any, Any], relative: str) -> list[Finding]:
    findings: list[Finding] = []

    if "permissions" not in document:
        findings.append(
            Finding.from_rule(
                RULE_MISSING_PERMISSIONS,
                file=relative,
                message="No top-level 'permissions' key found.",
                category=CATEGORY,
            )
        )
    elif _is_write_all(document["permissions"]):
        findings.append(
            Finding.from_rule(
                RULE_WRITE_ALL_PERMISSIONS,
                file=relative,
                message="Top-level 'permissions' is set to 'write-all'.",
                category=CATEGORY,
            )
        )

    triggers = _triggers(document)
    if "pull_request_target" in triggers:
        findings.append(
            Finding.from_rule(
                RULE_PULL_REQUEST_TARGET,
                file=relative,
                message="Workflow is triggered by 'pull_request_target'.",
                category=CATEGORY,
            )
        )

    return findings


def _is_write_all(permissions: Any) -> bool:
    return isinstance(permissions, str) and permissions.strip().lower() == "write-all"


def _triggers(document: dict[Any, Any]) -> set[str]:
    """Extract normalised trigger names from the ``on`` key.

    ``on`` may be a scalar, a list, or a mapping, and PyYAML may have coerced the
    key itself to ``True``.
    """
    if "on" in document:
        raw = document["on"]
    elif True in document:  # YAML 1.1 boolean coercion of the key 'on'
        raw = document[True]
    else:
        return set()

    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    if isinstance(raw, (list, tuple)):
        return {item for item in raw if isinstance(item, str)}
    return set()


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _yaml_problem(exc: yaml.YAMLError) -> tuple[str, int]:
    """Summarise a PyYAML error into a short message and a 1-based line number."""
    problem = getattr(exc, "problem", None)
    if not problem:
        problem = str(exc).splitlines()[0] if str(exc) else "invalid YAML"
    mark = getattr(exc, "problem_mark", None)
    line = (mark.line + 1) if mark is not None else 0
    return str(problem), line
