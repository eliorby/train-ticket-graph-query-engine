"""Bounded DFS path enumeration with cycle-edge annotation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.engine.filters import FilterContext, apply_filters
from app.graph.graph import Graph
from app.models.graph import Edge, Node


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


def _candidate_starts(graph: Graph, filter_names: list[str]) -> list[str]:
    """Derive start-node candidates from active filters."""
    if "publicSource" in filter_names:
        return graph.public_sources()
    return graph.node_names()


def _candidate_ends(
    graph: Graph, filter_names: list[str], ctx: FilterContext
) -> list[str]:
    """Derive end-node candidates from active filters."""
    if "sink" in filter_names:
        return graph.sinks(sink_kinds=ctx.sink_kinds)
    return graph.node_names()


def enumerate_routes(
    graph: Graph,
    filter_names: list[str],
    ctx: FilterContext,
    max_depth: int,
    max_results: int,
) -> tuple[list[Route], bool]:
    """Enumerate bounded simple paths matching the requested filters.

    Runs DFS over the cross-product of start and end candidates,
    keeping only simple paths (no repeated nodes). Paths must satisfy all requested filters.
    When ``max_results`` is reached, enumeration stops and ``truncated`` is returned as True.

    ``max_depth`` bounds the number of hops (edges), not nodes.
    """
    starts = _candidate_starts(graph, filter_names)
    ends = set(_candidate_ends(graph, filter_names, ctx))
    routes: list[Route] = []
    truncated = False

    def dfs(
        current: str,
        path: list[str],
        depth: int,
        seen_cycles: list[CycleEdge],
    ) -> None:
        nonlocal truncated
        if truncated:
            return

        if depth > max_depth:
            return

        on_path = set(path)
        local_cycles = [
            CycleEdge(from_node=current, to_node=neighbor)
            for neighbor in graph.neighbors(current)
            if neighbor in on_path
        ]
        accumulated_cycles = seen_cycles + local_cycles

        if current in ends and len(path) > 1:
            if apply_filters(path, graph, filter_names, ctx):
                routes.append(
                    Route(path=list(path), cycle_edges=accumulated_cycles)
                )
                if len(routes) >= max_results:
                    truncated = True
                    return

        if depth == max_depth:
            return

        for neighbor in graph.neighbors(current):
            if neighbor in on_path:
                continue
            path.append(neighbor)
            dfs(neighbor, path, depth + 1, accumulated_cycles)
            path.pop()
            if truncated:
                return

    for start in starts:
        if truncated:
            break
        dfs(start, [start], 0, [])

    return routes, truncated


def build_subgraph(
    graph: Graph,
    filter_names: list[str],
    ctx: FilterContext,
    max_depth: int,
    max_results: int,
) -> tuple[Graph, bool]:
    """Build a deduplicated node/edge subgraph covering all route paths."""
    node_names: set[str] = set()

    routes, truncated = enumerate_routes(
        graph,
        filter_names,
        ctx,
        max_depth,
        max_results,
    )
    for route in routes:
        node_names.update(route.path)

    nodes: dict[str, Node] = {}
    for name in graph.node_names():
        if name not in node_names:
            continue
        node = graph.get_node(name)
        if node is None:
            continue
        nodes[name] = node

    edge_map: defaultdict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        for target in edge.to:
            if edge.from_ in node_names and target in node_names:
                edge_map[edge.from_].add(target)

    edges = [
        Edge(from_=from_node, to=sorted(targets))
        for from_node, targets in sorted(edge_map.items())
    ]

    return Graph(nodes=nodes, adjacency={}, edges=edges), truncated


def vulnerable_nodes_on_path(path: list[str], graph: Graph) -> list[str]:
    """Return vulnerable node names appearing on a path, in path order."""
    return [node for node in path if graph.is_vulnerable(node)]
