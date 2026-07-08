"""API response schemas."""

from pydantic import BaseModel

from app.models.filters import Filter
from app.models.graph import Edge, Node
from app.models.truncation import TruncationReason


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
    """Graph query response."""

    truncated: bool
    truncation_reason: TruncationReason | None = None
    applied_filters: list[Filter]
    max_depth: int | None = None
    max_results: int | None = None
    max_dfs_steps: int | None = None
    summary: GraphSummary
    graph: GraphView
