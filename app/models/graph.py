"""Core graph entity models mirroring the source JSON schema."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Vulnerability(BaseModel):
    """A single vulnerability finding attached to a node."""

    file: str
    severity: str
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
    """A directed edge between nodes; ``to`` is always a list after normalization."""

    from_: str = Field(alias="from")
    to: list[str]

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)


class GraphPayload(BaseModel):
    """Raw graph document as stored in the JSON file."""

    nodes: list[Node]
    edges: list[Edge]
