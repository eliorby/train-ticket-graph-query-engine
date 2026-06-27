"""Application state holding the loaded graph and load-time issues."""

from __future__ import annotations

from dataclasses import dataclass

from app.graph.graph import Graph
from app.models.issue import Issue


@dataclass(frozen=True)
class AppState:
    """Immutable container for graph data loaded once at startup."""

    graph: Graph
    load_issues: list[Issue]
