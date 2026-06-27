"""Unit tests for graph loading and normalization."""

from app.graph.loader import load_graph


def test_normalizes_string_to_field(loaded_test_graph):
    """String-shaped ``to`` fields are coerced and recorded as info issues."""
    issues = loaded_test_graph.issues
    normalized = [i for i in issues if i.code == "normalized-to-field"]
    assert len(normalized) == 1
    assert "public-b" in normalized[0].message


def test_dangling_reference_excluded_from_adjacency(loaded_test_graph):
    """Dangling targets are excluded from traversal adjacency."""
    graph = loaded_test_graph.graph
    assert "undefined-node" not in graph.adjacency["service-c"]


def test_dangling_reference_recorded_as_error(loaded_test_graph):
    """Dangling node references are surfaced as error-severity issues."""
    dangling = [
        i for i in loaded_test_graph.issues if i.code == "dangling-node-reference"
    ]
    assert len(dangling) == 1
    assert "undefined-node" in dangling[0].message


def test_real_graph_catches_assurance_service_reference(loaded_real_graph):
    """The production graph must report the known assurance-service dangling ref."""
    dangling = [
        i
        for i in loaded_real_graph.issues
        if i.code == "dangling-node-reference"
    ]
    targets = {issue.message for issue in dangling}
    assert any("assurance-service" in message for message in targets)


def test_real_graph_normalizes_consign_edge(loaded_real_graph):
    """The consign-service edge with a string ``to`` is normalized."""
    normalized = [
        i for i in loaded_real_graph.issues if i.code == "normalized-to-field"
    ]
    assert any("consign-service" in issue.message for issue in normalized)
