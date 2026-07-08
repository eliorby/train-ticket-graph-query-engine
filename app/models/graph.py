"""Core graph entity models mirroring the source JSON / API schemas."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilitySeverity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


VULNERABILITY_SEVERITY_RANK: dict[VulnerabilitySeverity, int] = {
    VulnerabilitySeverity.INFO: 0,
    VulnerabilitySeverity.LOW: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.HIGH: 3,
    VulnerabilitySeverity.CRITICAL: 4,
}


def severity_at_least(
    severity: VulnerabilitySeverity,
    minimum: VulnerabilitySeverity,
) -> bool:
    """Return whether severity is greater than or equal to the requested threshold."""
    return (
        VULNERABILITY_SEVERITY_RANK[severity]
        >= VULNERABILITY_SEVERITY_RANK[minimum]
    )


class Vulnerability(BaseModel):
    """A single vulnerability finding attached to a node."""

    file: str
    severity: VulnerabilitySeverity
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Node(BaseModel):
    """A node in the service-dependency graph."""

    name: str
    kind: str = "service"
    language: str | None = None
    path: str | None = None
    publicExposed: bool = False
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    """
    A directed edge between nodes;
    ``to`` is always a list after normalization.
    """

    from_: str = Field(alias="from")
    to: list[str]

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)
