"""Graph endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.config import (
    DEFAULT_MAX_DEPTH, MAX_DEPTH_CEILING,
    DEFAULT_MAX_RESULTS, MAX_RESULTS_CEILING,
    DEFAULT_MAX_DFS_STEPS, MAX_DFS_STEPS_CEILING
)
from app.dependencies import get_app_state
from app.engine.enumerator import build_subgraph
from app.engine.filters import FILTER_REGISTRY, FilterContext
from app.models.filters import Filter
from app.models.api.graph import GraphResponse, GraphView, GraphSummary
from app.state import AppState


router = APIRouter(tags=["graph"])


def _parse_filters(filters: str | None) -> tuple[Filter, ...]:
    """Parse, validate, and dedupe comma-separated filter names."""
    if not filters or not filters.strip():
        return ()

    parsed_filters: list[Filter] = []
    seen: set[Filter] = set()
    unknown: list[str] = []

    for raw_name in filters.split(","):
        name = raw_name.strip()
        if not name:
            continue

        try:
            filter_ = Filter(name)
        except ValueError:
            unknown.append(name)
            continue

        if filter_ in seen:
            continue

        parsed_filters.append(filter_)
        seen.add(filter_)

    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown filter(s): {', '.join(unknown)}. "
                f"Available filters: {', '.join(filter_.value for filter_ in Filter)}"
            ),
        )

    # Defensive check: enum value exists but is not registered.
    unregistered = [
        filter_.value
        for filter_ in parsed_filters
        if filter_ not in FILTER_REGISTRY
    ]
    if unregistered:
        raise HTTPException(
            status_code=500,
            detail=f"Filter(s) defined but not registered: {', '.join(unregistered)}",
        )

    return tuple(parsed_filters)


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
    filters_raw: str | None = Query(
        default=None,
        alias="filters",
        description="Comma-separated filter names (AND semantics).",
    ),
    max_depth_raw: int = Query(default=DEFAULT_MAX_DEPTH, ge=1, alias="maxDepth"),
    max_results_raw: int = Query(default=DEFAULT_MAX_RESULTS, ge=1, alias="maxResults"),
    max_dfs_steps_raw: int = Query(default=DEFAULT_MAX_DFS_STEPS, ge=1, alias="maxDfsSteps"),
    sink_kinds_raw: str | None = Query(
        default=None,
        alias="sinkKinds",
        description="Comma-separated sink kinds when using the sink filter.",
    ),
    state: AppState = Depends(get_app_state)
) -> GraphResponse:
    """
    Return a graph which satisfies all requested filters (AND semantics).
    Return the full normalized graph if no filters are specified.
    """
    filters: tuple[Filter, ...] = _parse_filters(filters_raw)

    if filters:
        sink_kinds: frozenset[str] | None = None
        if sink_kinds_raw and sink_kinds_raw.strip():
            sink_kinds = frozenset(
                kind.strip()
                for kind in sink_kinds_raw.split(",")
                if kind.strip()
            )
        ctx = FilterContext(sink_kinds=sink_kinds)
        max_depth = _clamp(max_depth_raw, MAX_DEPTH_CEILING, "maxDepth")
        max_results = _clamp(max_results_raw, MAX_RESULTS_CEILING, "maxResults")
        max_dfs_steps = _clamp(max_dfs_steps_raw, MAX_DFS_STEPS_CEILING, "maxDfsSteps")
        graph, truncated, truncation_reason = build_subgraph(state.graph, filters, ctx, max_depth, max_results, max_dfs_steps)
    else:
        max_depth, max_results, max_dfs_steps = None, None, None
        graph, truncated, truncation_reason = state.graph, False, None

    return GraphResponse(
        truncated=truncated,
        truncation_reason=truncation_reason,
        applied_filters=list(filters),
        max_depth=max_depth,
        max_results=max_results,
        max_dfs_steps=max_dfs_steps,
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
