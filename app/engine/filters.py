"""Filter predicate registry for route queries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.graph.graph import Graph

Path = list[str]
FilterPredicate = Callable[[Path, Graph, "FilterContext"], bool]


@dataclass(frozen=True)
class FilterContext:
    """Per-request parameters passed to filter predicates."""

    sink_kinds: frozenset[str] | None = None


@dataclass(frozen=True)
class FilterDefinition:
    """Metadata and predicate for a registered filter."""

    name: str
    scope: str
    description: str
    predicate: FilterPredicate
    parameters: tuple[dict[str, str], ...] = ()


def is_public_source(path: Path, graph: Graph, _ctx: FilterContext) -> bool:
    """Return True when the path starts at a publicly exposed node."""
    if not path:
        return False
    return graph.is_public_source(path[0])


def is_sink(path: Path, graph: Graph, ctx: FilterContext) -> bool:
    """Return True when the path ends at a non-service sink node."""
    if not path:
        return False
    return graph.is_sink(path[-1], sink_kinds=ctx.sink_kinds)


def is_vulnerable(path: Path, graph: Graph, _ctx: FilterContext) -> bool:
    """Return True when any node on the path has vulnerabilities."""
    return any(graph.is_vulnerable(node) for node in path)


FILTER_REGISTRY: dict[str, FilterDefinition] = {
    "publicSource": FilterDefinition(
        name="publicSource",
        scope="path-start",
        description="Path must start at a publicly exposed node.",
        predicate=is_public_source,
    ),
    "sink": FilterDefinition(
        name="sink",
        scope="path-end",
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
    "vulnerable": FilterDefinition(
        name="vulnerable",
        scope="path-any",
        description="At least one node on the path must have vulnerabilities.",
        predicate=is_vulnerable,
    ),
}


def get_filter_info() -> list[FilterDefinition]:
    """Return all registered filter definitions."""
    return list(FILTER_REGISTRY.values())


def apply_filters(
    path: Path,
    graph: Graph,
    filter_names: list[str],
    ctx: FilterContext,
) -> bool:
    """Return True when a path satisfies all requested filters (AND semantics)."""
    for name in filter_names:
        definition = FILTER_REGISTRY[name]
        if not definition.predicate(path, graph, ctx):
            return False
    return True
