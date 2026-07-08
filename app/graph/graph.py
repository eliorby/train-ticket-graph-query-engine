"""Runtime in-memory graph abstraction built from normalized JSON."""

from __future__ import annotations

from collections.abc import Collection

from app.models.graph import Edge, Node


class Graph:
    """
    Adjacency-list graph with node metadata and traversal-safe edges.

    Only edges whose targets exist in the node map are included in the
    adjacency structure used for path enumeration. All normalized edges
    (including those with dangling targets) are retained for API responses.
    """

    def __init__(
        self,
        nodes: dict[str, Node],
        edges: list[Edge],
        adjacency: dict[str, list[str]],
    ) -> None:
        self._nodes = nodes
        self._edges = edges
        self._adjacency = adjacency

    @property
    def nodes(self) -> dict[str, Node]:
        """All nodes keyed by name."""
        return self._nodes

    @property
    def adjacency(self) -> dict[str, list[str]]:
        """Outgoing neighbors for traversal (dangling targets excluded)."""
        return self._adjacency

    @property
    def edges(self) -> list[Edge]:
        """All normalized edges, including those with dangling targets."""
        return self._edges

    def get_node(self, name: str) -> Node | None:
        """Return node metadata by name, or ``None`` if unknown."""
        return self._nodes.get(name)

    def neighbors(self, name: str) -> list[str]:
        """Return traversal-safe outgoing neighbors for a node."""
        return self._adjacency.get(name, [])

    def node_names(self) -> list[str]:
        """Return all node names in stable insertion order."""
        return list(self._nodes.keys())

    def is_public_source(self, name: str) -> bool:
        """Return whether a node is publicly exposed."""
        node = self._nodes.get(name)
        return node is not None and node.publicExposed is True

    def is_sink(self, name: str, sink_kinds: Collection[str] | None = None) -> bool:
        """
        Return whether a node qualifies as a sink.

        A sink is any node whose ``kind`` is not ``service``.
        When ``sink_kinds`` is provided, the node's kind must also be in that set.
        """
        node = self._nodes.get(name)
        if node is None or node.kind == "service":
            return False
        if sink_kinds is None:
            return True
        return node.kind in sink_kinds

    def is_vulnerable(self, name: str) -> bool:
        """Return whether a node has at least one vulnerability."""
        node = self._nodes.get(name)
        return node is not None and len(node.vulnerabilities) > 0

    def public_sources(self) -> list[str]:
        """Return names of all publicly exposed nodes."""
        return [
            n for n, node in self._nodes.items()
            if node.publicExposed
        ]

    def sinks(self, sink_kinds: Collection[str] | None = None) -> list[str]:
        """Return names of all sink nodes, optionally filtered by kind."""
        return [
            n for n in self._nodes
            if self.is_sink(n, sink_kinds=sink_kinds)
        ]

    def vulnerable_nodes(self) -> list[str]:
        """Return names of all nodes with non-empty vulnerability lists."""
        return [
            n for n in self._nodes
            if self.is_vulnerable(n)
        ]

    def vulnerable_nodes_on_path(self, path: list[str]) -> list[str]:
        """Return vulnerable node names appearing on a path, in path order."""
        return [
            n for n in path
            if self.is_vulnerable(n)
        ]

    def node_kind_counts(self) -> dict[str, int]:
        """Return a count of nodes grouped by ``kind``."""
        counts: dict[str, int] = {}
        for node in self._nodes.values():
            counts[node.kind] = counts.get(node.kind, 0) + 1
        return counts
