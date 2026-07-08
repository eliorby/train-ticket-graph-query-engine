"""Given the requested filters, how should the engine execute the search?"""

from dataclasses import dataclass

from app.engine.filters import FILTER_REGISTRY, FilterContext, FilterScope, apply_filters
from app.graph.graph import Graph
from app.models.filters import Filter


@dataclass(frozen=True)
class QueryPlan:
    start_filters: tuple[Filter, ...]
    end_filters: tuple[Filter, ...]
    path_filters: tuple[Filter, ...]


def build_query_plan(filters: tuple[Filter, ...]) -> QueryPlan:
    start_filters: list[Filter] = []
    end_filters: list[Filter] = []
    path_filters: list[Filter] = []

    for filter_ in filters:
        definition = FILTER_REGISTRY[filter_]

        if definition.scope == FilterScope.START:
            start_filters.append(filter_)
        elif definition.scope == FilterScope.END:
            end_filters.append(filter_)
        elif definition.scope == FilterScope.PATH:
            path_filters.append(filter_)
        else:
            raise ValueError(f"Unsupported filter scope: {definition.scope}")

    return QueryPlan(
        start_filters=tuple(start_filters),
        end_filters=tuple(end_filters),
        path_filters=tuple(path_filters),
    )


def candidate_starts(
    graph: Graph,
    plan: QueryPlan,
    ctx: FilterContext,
) -> list[str]:
    if not plan.start_filters:
        return graph.node_names()

    return [
        n for n in graph.node_names()
        if apply_filters(graph, [n], plan.start_filters, ctx)
    ]


def candidate_ends(
    graph: Graph,
    plan: QueryPlan,
    ctx: FilterContext,
) -> set[str]:
    if not plan.end_filters:
        return set(graph.node_names())

    return {
        n for n in graph.node_names()
        if apply_filters(graph, [n], plan.end_filters, ctx)
    }
