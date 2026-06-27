"""Graph endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.config import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_RESULTS,
    MAX_DEPTH_CEILING,
    MAX_RESULTS_CEILING,
)
from app.dependencies import get_app_state
from app.engine.enumerator import build_subgraph
from app.engine.filters import FILTER_REGISTRY, FilterContext
from app.models.responses import GraphResponse, GraphSummary, GraphView
from app.state import AppState


router = APIRouter(tags=["graph"])


def _parse_filters(filters: str | None) -> list[str]:
    """Parse and validate comma-separated filter names."""
    if not filters or not filters.strip():
        return []
    names = [name.strip() for name in filters.split(",") if name.strip()]
    unknown = [name for name in names if name not in FILTER_REGISTRY]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown filter(s): {', '.join(unknown)}",
        )
    return names


def _clamp(value: int, ceiling: int, param_name: str) -> int:
    """Clamp a positive integer query param to the server-side ceiling."""
    if value < 1:
        raise HTTPException(
            status_code=400,
            detail=f"{param_name} must be at least 1.",
        )
    return min(value, ceiling)


@router.get("/graph", response_model=GraphResponse)
def get_graph(
    filters: str | None = Query(
        default=None,
        description="Comma-separated filter names (AND semantics).",
    ),
    maxDepth: int = Query(default=DEFAULT_MAX_DEPTH, ge=1),
    maxResults: int = Query(default=DEFAULT_MAX_RESULTS, ge=1),
    sinkKinds: str | None = Query(
        default=None,
        description="Comma-separated sink kinds when using the sink filter.",
    ),
    state: AppState = Depends(get_app_state)
) -> GraphResponse:
    """
    Return a graph which satisfies all requested filters (AND semantics).
    Return the full normalized graph if no filters are specified.
    """
    filter_names = _parse_filters(filters)

    if filter_names:
        sink_kinds: frozenset[str] | None = None
        if sinkKinds and sinkKinds.strip():
            sink_kinds = frozenset(
                kind.strip() for kind in sinkKinds.split(",") if kind.strip()
            )
        ctx = FilterContext(sink_kinds=sink_kinds)
        max_depth = _clamp(maxDepth, MAX_DEPTH_CEILING, "maxDepth")
        max_results = _clamp(maxResults, MAX_RESULTS_CEILING, "maxResults")
        graph, truncated = build_subgraph(state.graph, filter_names, ctx, max_depth, max_results)
    else:
        max_depth, max_results = None, None
        graph, truncated = state.graph, False

    return GraphResponse(
        truncated=truncated,
        applied_filters=filter_names,
        max_depth=max_depth,
        max_results=max_results,
        summary=GraphSummary(
            node_count=len(graph.nodes),
            edge_count=len(graph.edges),
            node_kinds=graph.node_kind_counts(),
            public_sources=graph.public_sources(),
            sinks=graph.sinks(),
            vulnerable_nodes=graph.vulnerable_nodes(),
        ),
        graph=GraphView(
            nodes=list(graph.nodes.values()),
            edges=graph.edges,
        ),
    )
