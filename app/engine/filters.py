"""Filter predicate registry for route queries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.graph.graph import Graph
from app.models.filters import Filter


@dataclass(frozen=True)
class FilterContext:
    """Per-request parameters passed to filter predicates."""

    sink_kinds: frozenset[str] | None = None


FilterPredicate = Callable[[Graph, list[str], FilterContext], bool]


@dataclass(frozen=True)
class FilterDefinition:
    """Metadata and predicate for a registered filter."""

    name: Filter
    scope: FilterScope
    description: str
    predicate: FilterPredicate
    parameters: tuple[dict[str, Any], ...] = ()


class FilterScope(StrEnum):
    START = "path-start"
    END = "path-end"
    PATH = "path-any"


def is_public_source(
        graph: Graph,
        path: list[str],
        _ctx: FilterContext,
) -> bool:
    """Return True when the path starts at a publicly exposed node."""
    if not path:
        return False
    return graph.is_public_source(path[0])


def is_sink(
        graph: Graph,
        path: list[str],
        ctx: FilterContext,
) -> bool:
    """Return True when the path ends at a non-service sink node."""
    if not path:
        return False
    return graph.is_sink(path[-1], sink_kinds=ctx.sink_kinds)


def is_vulnerable(
        graph: Graph,
        path: list[str],
        _ctx: FilterContext,
) -> bool:
    """Return True when any node on the path has vulnerabilities."""
    return any(graph.is_vulnerable(node) for node in path)


FILTER_REGISTRY: dict[Filter, FilterDefinition] = {
    Filter.PUBLIC_SOURCE: FilterDefinition(
        name=Filter.PUBLIC_SOURCE,
        scope=FilterScope.START,
        description="Path must start at a publicly exposed node.",
        predicate=is_public_source,
    ),
    Filter.SINK: FilterDefinition(
        name=Filter.SINK,
        scope=FilterScope.END,
        description=(
            "Path must end at a non-service node (sink). "
            "Optionally narrow with the sinkKinds query parameter."
        ),
        predicate=is_sink,
        parameters=(
            {
                "name": "sinkKinds",
                "type": "string",
                "description": "Comma-separated sink kinds to match (e.g. rds,sqs).",
            },
        ),
    ),
    Filter.VULNERABLE: FilterDefinition(
        name=Filter.VULNERABLE,
        scope=FilterScope.PATH,
        description="At least one node on the path must have vulnerabilities.",
        predicate=is_vulnerable,
    ),
}


def get_filter_info() -> list[FilterDefinition]:
    """Return all registered filter definitions."""
    return list(FILTER_REGISTRY.values())


def apply_filters(
        graph: Graph,
        path: list[str],
        filters: tuple[Filter, ...],
        ctx: FilterContext,
) -> bool:
    """Return True when a path satisfies all requested filters (AND semantics)."""
    for filter_ in filters:
        definition = FILTER_REGISTRY[filter_]  # validated by API layer
        if not definition.predicate(graph, path, ctx):
            return False
    return True
