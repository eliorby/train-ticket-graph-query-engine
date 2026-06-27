"""API response schemas."""

from typing import Any

from pydantic import BaseModel, Field

from app.models.graph import Edge, Node


class GraphView(BaseModel):
    """Standard graph payload returned by graph-oriented endpoints."""

    nodes: list[Node]
    edges: list[Edge]


class GraphSummary(BaseModel):
    """Descriptive statistics about the graph."""

    node_count: int
    edge_count: int
    node_kinds: dict[str, int]
    public_sources: list[str]
    sinks: list[str]
    vulnerable_nodes: list[str]


class GraphResponse(BaseModel):

    truncated: bool
    applied_filters: list[str]
    max_depth: int | None = None
    max_results: int | None = None
    summary: GraphSummary
    graph: GraphView


class GraphValidateResponse(BaseModel):
    """Structural integrity report from validator registry."""

    issues: list["IssueResponse"]
    valid: bool


class IssueResponse(BaseModel):
    """Issue as returned by the validate endpoint."""

    code: str
    severity: str
    message: str


class FilterInfo(BaseModel):
    """Self-describing metadata for a registered filter predicate."""

    name: str
    scope: str
    description: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)


class FiltersResponse(BaseModel):
    """List of available route filters."""

    filters: list[FilterInfo]
