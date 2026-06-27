"""Unit tests for graph validators."""

from app.engine.validators import run_validators
from app.graph.loader import load_graph
from tests.conftest import REAL_GRAPH_PATH, TEST_GRAPH_PATH


def test_validators_surface_fixture_issues():
    result = load_graph(TEST_GRAPH_PATH)
    issues = run_validators(result.graph, result.issues)
    codes = {issue.code for issue in issues}
    assert "dangling-node-reference" in codes
    assert "normalized-to-field" in codes


def test_validators_catch_assurance_service_on_real_graph():
    result = load_graph(REAL_GRAPH_PATH)
    issues = run_validators(result.graph, result.issues)
    assert any(
        issue.code == "dangling-node-reference" and "assurance-service" in issue.message
        for issue in issues
    )
