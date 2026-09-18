"""Expected, user-facing failures for agent-identity-guard."""

from __future__ import annotations

__all__ = ["AgentGuardError", "GitAuditError", "WorkflowScanError"]


class AgentGuardError(Exception):
    """Base class for failures the CLI reports instead of crashing on."""


class WorkflowScanError(AgentGuardError):
    """Raised when the workflow scan cannot run at all."""


class GitAuditError(AgentGuardError):
    """Raised when the git history audit cannot run at all."""
