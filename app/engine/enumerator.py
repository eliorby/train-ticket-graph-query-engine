"""Bounded DFS path enumeration with cycle-edge annotation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from itertools import pairwise

from app.engine.filters import FilterContext, apply_filters
from app.engine.query_plan import build_query_plan, candidate_starts, candidate_ends
from app.graph.graph import Graph
from app.models.filters import Filter
from app.models.graph import Edge, Node
from app.models.truncation import TruncationReason


@dataclass(frozen=True)
class CycleEdge:
    """A back-edge detected from the current path tail."""

    from_node: str
    to_node: str


@dataclass
class Route:
    """An enumerated simple path with optional cycle-edge annotations."""

    path: list[str]
    cycle_edges: list[CycleEdge] = field(default_factory=list)

    @property
    def length(self) -> int:
        """Number of hops (edges) in the path."""
        return max(0, len(self.path) - 1)

    @property
    def has_cycle_edges(self) -> bool:
        """Whether any back-edges were detected from the path tail."""
        return bool(self.cycle_edges)


def enumerate_routes(
    graph: Graph,
    filters: tuple[Filter, ...],
    ctx: FilterContext,
    max_depth: int,
    max_results: int,
    max_dfs_steps: int
) -> tuple[list[Route], bool, TruncationReason | None]:
    """
    Enumerate bounded simple paths matching the requested filters.

    Runs DFS (Depth-First Search) over start candidates.
    """
    plan = build_query_plan(filters)

    start_node_names = candidate_starts(graph, plan, ctx)
    end_node_names = set(candidate_ends(graph, plan, ctx))

    routes: list[Route] = []
    steps = 0
    truncated = False
    truncation_reason: TruncationReason | None = None

    def dfs(
        current: str,
        path: list[str],
        on_path: set[str],
        depth: int,
        seen_cycles: list[CycleEdge],
    ) -> None:
        """
        Depth-First Search.
        Runs over the cross-product of a start candidate and multiple end candidates,
            keeping only simple paths (no repeated nodes) that satisfy all requested filters.

        ``max_depth`` bounds the number of hops (edges), not nodes.
        When either ``max_results`` or ``max_dfs_steps`` is reached,
            enumeration stops and ``truncated`` is returned as True.
        """
        nonlocal steps, truncated, truncation_reason

        if truncated or depth > max_depth:
            return

        if steps >= max_dfs_steps:
            truncated = True
            truncation_reason = TruncationReason.MAX_DFS_STEPS
            return
        steps += 1

        neighbors = graph.neighbors(current)

        local_cycles = [
            CycleEdge(from_node=current, to_node=node_name)
            for node_name in neighbors
            if node_name in on_path
        ]
        accumulated_cycles = seen_cycles + local_cycles

        if current in end_node_names and len(path) > 1:
            if apply_filters(graph, path, plan.path_filters, ctx):
                routes.append(
                    Route(path=list(path), cycle_edges=accumulated_cycles)
                )
                if len(routes) >= max_results:
                    truncated = True
                    truncation_reason = TruncationReason.MAX_RESULTS
                    return

        if depth == max_depth:
            return

        for neighbor in neighbors:
            if neighbor in on_path:
                continue

            path.append(neighbor)
            on_path.add(neighbor)

            dfs(neighbor, path, on_path, depth + 1, accumulated_cycles)

            on_path.remove(neighbor)
            path.pop()

            if truncated:
                return

    for start in start_node_names:
        if truncated:
            break
        dfs(start, [start], {start}, 0, [])

    return routes, truncated, truncation_reason


def build_subgraph(
    graph: Graph,
    filters: tuple[Filter, ...],
    ctx: FilterContext,
    max_depth: int,
    max_results: int,
    max_dfs_steps: int,
) -> tuple[Graph, bool, TruncationReason | None]:
    """Build a deduplicated node/edge subgraph covering only matched route paths."""

    routes, truncated, truncation_reason = enumerate_routes(graph, filters, ctx, max_depth, max_results, max_dfs_steps)

    node_names: set[str] = set()
    edge_map: defaultdict[str, set[str]] = defaultdict(set)

    # collect all node names & edges from matched routes
    for route in routes:
        node_names.update(route.path)
        for from_node, to_node in pairwise(route.path):  # iterate over adjacent node pairs
            edge_map[from_node].add(to_node)

    nodes: dict[str, Node] = {
        name: node
        for name, node in graph.nodes.items()  # preserves the original graph node order
        if name in node_names
    }

    edges = [
        Edge(from_=from_node, to=sorted(targets))
        for from_node, targets in sorted(edge_map.items())
    ]

    adjacency: dict[str, list[str]] = {
        from_node: sorted(targets)
        for from_node, targets in edge_map.items()
    }

    return Graph(nodes=nodes, edges=edges, adjacency=adjacency), truncated, truncation_reason
