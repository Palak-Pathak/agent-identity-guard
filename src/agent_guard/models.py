"""Shared, dependency-free domain models for agent-identity-guard.

Every audit rule produces :class:`Finding` objects. A finding points at a file,
carries a :class:`Severity`, and embeds the :class:`Rule` that produced it so the
CLI (or any other consumer) can render both the finding and the "why" behind it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["Finding", "Rule", "Severity"]


class Severity(str, Enum):
    """Ordered severity levels used across every audit rule.

    Inherits from ``str`` so it serialises cleanly to JSON and renders directly
    in Rich. Ordering is by risk (most severe first) rather than alphabetically.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Sort key where ``0`` is the most severe level."""
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True, slots=True)
class Rule:
    """Static description of a single audit check."""

    id: str
    title: str
    severity: Severity
    description: str

    def __str__(self) -> str:
        return f"{self.id}: {self.title}"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single audit result.

    Attributes:
        file: Repository-relative path the finding applies to.
        severity: Effective severity, normally ``rule.severity``.
        rule: The rule that produced the finding (its details live here).
        message: Human readable, finding-specific explanation.
        category: Origin of the finding, e.g. ``"workflow"`` or ``"git-history"``.
        line: Optional 1-based line number for YAML parse errors.
    """

    file: str
    severity: Severity
    rule: Rule
    message: str
    category: str
    line: int | None = None

    @classmethod
    def from_rule(
        cls,
        rule: Rule,
        *,
        file: str,
        message: str,
        category: str,
        line: int | None = None,
    ) -> Finding:
        """Build a finding, inheriting the severity declared by ``rule``."""
        return cls(
            file=file,
            severity=rule.severity,
            rule=rule,
            message=message,
            category=category,
            line=line,
        )
