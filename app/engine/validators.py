"""Graph-level validator registry."""

from __future__ import annotations

from collections.abc import Callable

from app.graph.graph import Graph
from app.models.issue import Issue, IssueCode


ValidatorFn = Callable[[Graph, list[Issue]], list[Issue]]


def detect_dangling_references(
        _graph: Graph,
        load_issues: list[Issue]
) -> list[Issue]:
    """Surface dangling node references recorded at load time."""
    return [
        issue for issue in load_issues
        if issue.code == IssueCode.DANGLING_NODE_REFERENCE.value
    ]


def detect_normalized_shapes(
        _graph: Graph,
        load_issues: list[Issue]
) -> list[Issue]:
    """Surface edge shape normalizations recorded at load time."""
    return [
        issue for issue in load_issues
        if issue.code == IssueCode.NORMALIZED_TO_FIELD.value
    ]


VALIDATOR_REGISTRY: dict[str, ValidatorFn] = {
    "danglingNodeReferences": detect_dangling_references,
    "normalizedShapes": detect_normalized_shapes,
}


def run_validators(graph: Graph, load_issues: list[Issue]) -> list[Issue]:
    """Run all registered validators and return combined issues."""
    issues: list[Issue] = []
    for validator in VALIDATOR_REGISTRY.values():
        issues.extend(validator(graph, load_issues))
    return issues
