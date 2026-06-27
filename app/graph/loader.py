"""Load and normalize graph JSON into an in-memory Graph."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.graph.graph import Graph
from app.models.graph import Edge, Node, Vulnerability
from app.models.issue import Issue


@dataclass
class LoadResult:
    """Outcome of loading a graph file, including validation side-effects."""

    graph: Graph
    issues: list[Issue] = field(default_factory=list)


def _normalize_to_field(raw_to: str | list[str]) -> tuple[list[str], bool]:
    """Coerce a string ``to`` value into a single-element list.

    Returns the normalized list and whether coercion was performed.
    """
    if isinstance(raw_to, str):
        return [raw_to], True
    return list(raw_to), False


def _parse_node(raw: dict[str, Any]) -> Node:
    """Parse a raw node dict into a Node model."""
    vulnerabilities = [
        Vulnerability(**v) for v in raw.get("vulnerabilities", [])
    ]
    return Node(
        name=raw["name"],
        kind=raw.get("kind", "service"),
        language=raw.get("language"),
        path=raw.get("path"),
        publicExposed=raw.get("publicExposed", False),
        vulnerabilities=vulnerabilities,
        metadata=raw.get("metadata", {}),
    )


def load_graph(path: Path) -> LoadResult:
    """Load a graph JSON file, normalize edge shapes, and build adjacency.

    Dangling node references are recorded as validation issues and excluded
    from the adjacency map so traversal cannot follow invalid edges.
    """
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)

    issues: list[Issue] = []
    nodes: dict[str, Node] = {}
    for raw_node in data.get("nodes", []):
        node = _parse_node(raw_node)
        nodes[node.name] = node

    normalized_edges: list[Edge] = []
    adjacency: dict[str, list[str]] = {name: [] for name in nodes}

    for raw_edge in data.get("edges", []):
        from_node = raw_edge["from"]
        to_list, was_normalized = _normalize_to_field(raw_edge["to"])

        if was_normalized:
            issues.append(
                Issue(
                    code="normalized-to-field",
                    severity="info",
                    message=(
                        f"Edge from '{from_node}' had a string 'to' field; "
                        f"normalized to a single-element array."
                    ),
                )
            )

        edge = Edge(from_=from_node, to=to_list)
        normalized_edges.append(edge)

        if from_node not in nodes:
            continue

        for target in to_list:
            if target not in nodes:
                issues.append(
                    Issue(
                        code="dangling-node-reference",
                        severity="error",
                        message=(
                            f"Edge from '{from_node}' references undefined "
                            f"node '{target}'."
                        ),
                    )
                )
                continue
            adjacency[from_node].append(target)

    graph = Graph(nodes=nodes, adjacency=adjacency, edges=normalized_edges)
    return LoadResult(graph=graph, issues=issues)
