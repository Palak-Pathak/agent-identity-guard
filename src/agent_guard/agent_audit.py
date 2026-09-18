"""Audit git history for bot/agent identities rewriting CI pipelines.

The threat model is straightforward: an automated agent should not be silently
rewriting the pipeline that executes with repository credentials. Any commit
authored by a recognised bot/agent signature that touches ``.github/workflows/``
is reported as CRITICAL.
"""

from __future__ import annotations

import re
from pathlib import Path

from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError
from git.objects.commit import Commit

from .errors import GitAuditError
from .models import Finding, Rule, Severity

__all__ = [
    "BOT_SIGNATURE_PATTERNS",
    "RULE_AGENT_WORKFLOW_TAMPERING",
    "audit_agent_commits",
    "detect_agent",
]

DEFAULT_MAX_COMMITS = 50
CATEGORY = "git-history"
WORKFLOWS_PREFIX = ".github/workflows/"

# Ordered specific-first so `detect_agent` reports the most descriptive label
# (e.g. "dependabot" rather than the generic "[bot]").
BOT_SIGNATURE_PATTERNS: tuple[str, ...] = (
    r"dependabot",
    r"renovate",
    r"github-actions",
    r"copilot",
    r"cursor",
    r"codex",
    r"claude",
    r"devin",
    r"openhands",
    r"coderabbit",
    r"windsurf",
    r"sweep-ai",
    r"\[bot\]",
)

BOT_SIGNATURE_RE = re.compile("|".join(BOT_SIGNATURE_PATTERNS), re.IGNORECASE)

RULE_AGENT_WORKFLOW_TAMPERING = Rule(
    id="AG-AGENT-001",
    title="Bot/agent commit modifies CI workflow files",
    severity=Severity.CRITICAL,
    description=(
        "An automated identity authored a commit that changes files under "
        "'.github/workflows/'. Automated agents should not silently rewrite the "
        "pipeline that executes with repository credentials; treat this as "
        "unauthorised pipeline tampering until reviewed."
    ),
)


def detect_agent(signature: str) -> str | None:
    """Return the bot/agent token matched in *signature*, or ``None``."""
    match = BOT_SIGNATURE_RE.search(signature)
    return match.group(0) if match else None


def audit_agent_commits(
    repo_path: Path | str, max_commits: int = DEFAULT_MAX_COMMITS
) -> list[Finding]:
    """Inspect the most recent *max_commits* and flag agent workflow tampering.

    Args:
        repo_path: Path to the repository root.
        max_commits: How far back to walk the history.

    Raises:
        GitAuditError: if *repo_path* is missing or not a git repository.
    """
    with _open_repo(repo_path) as repo:
        if not repo.head.is_valid():
            return []  # No commits yet: nothing to inspect.

        findings: list[Finding] = []
        for commit in repo.iter_commits(max_count=max_commits):
            signature = _author_signature(commit)
            agent = detect_agent(signature)
            if agent is None:
                continue

            for path in _changed_files(commit):
                if not _is_workflow_path(path):
                    continue
                findings.append(
                    Finding.from_rule(
                        RULE_AGENT_WORKFLOW_TAMPERING,
                        file=path,
                        message=(
                            f"Automated identity '{agent}' edited this workflow in "
                            f"commit {commit.hexsha[:8]} ({_subject(commit)}), "
                            f"authored by {signature}."
                        ),
                        category=CATEGORY,
                    )
                )
        return findings


def _open_repo(repo_path: Path | str) -> Repo:
    path = Path(repo_path)
    if not path.exists():
        raise GitAuditError(f"Repository path does not exist: {path}")
    try:
        return Repo(path)
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise GitAuditError(f"Not a git repository: {path}") from exc


def _author_signature(commit: Commit) -> str:
    name = commit.author.name or ""
    email = commit.author.email or ""
    return f"{name} <{email}>".strip()


def _changed_files(commit: Commit) -> list[str]:
    """Return repo-relative paths touched by *commit* (empty on unreadable diffs)."""
    try:
        return [str(path) for path in commit.stats.files]
    except (GitCommandError, ValueError):
        return []


def _is_workflow_path(path: str) -> bool:
    return path.replace("\\", "/").lower().startswith(WORKFLOWS_PREFIX)


def _subject(commit: Commit) -> str:
    summary = _as_text(commit.summary).replace('"', "'")
    return summary[:72]


def _as_text(value: object) -> str:
    """Normalise GitPython's ``Union[str, bytes]`` attributes to ``str``."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)
