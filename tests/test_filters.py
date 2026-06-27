"""Unit tests for filter predicates."""

import pytest

from app.engine.filters import FilterContext, apply_filters
from app.graph.loader import load_graph
from tests.conftest import TEST_GRAPH_PATH


@pytest.fixture
def graph():
    """Graph built from the synthetic fixture."""
    return load_graph(TEST_GRAPH_PATH).graph


def test_public_source_predicate(graph):
    path = ["public-b", "service-c"]
    assert apply_filters(path, graph, ["publicSource"], FilterContext()) is True
    assert apply_filters(["service-c", "sink-db"], graph, ["publicSource"], FilterContext()) is False


def test_sink_predicate(graph):
    path = ["public-b", "service-c", "sink-db"]
    assert apply_filters(path, graph, ["sink"], FilterContext()) is True
    assert apply_filters(["public-b", "service-c"], graph, ["sink"], FilterContext()) is False


def test_sink_predicate_with_sink_kinds(graph):
    path = ["public-b", "service-c", "sink-db"]
    ctx = FilterContext(sink_kinds=frozenset({"rds"}))
    assert apply_filters(path, graph, ["sink"], ctx) is True

    ctx_sqs = FilterContext(sink_kinds=frozenset({"sqs"}))
    assert apply_filters(path, graph, ["sink"], ctx_sqs) is False


def test_vulnerable_predicate(graph):
    path = ["public-b", "service-c", "service-d"]
    assert apply_filters(path, graph, ["vulnerable"], FilterContext()) is True
    assert apply_filters(["public-b", "service-c"], graph, ["vulnerable"], FilterContext()) is False


def test_combined_filters_and_semantics(graph):
    path = ["public-b", "service-c", "service-d", "sink-queue"]
    filters = ["publicSource", "sink", "vulnerable"]
    assert apply_filters(path, graph, filters, FilterContext()) is True

    missing_vuln = ["public-b", "service-c", "sink-db"]
    assert apply_filters(missing_vuln, graph, filters, FilterContext()) is False
