"""Unit tests for filter predicates."""

import pytest

from app.engine.filters import FilterContext, apply_filters
from app.graph.loader import load_graph
from app.models.filters import Filter

from tests.conftest import TEST_GRAPH_PATH


@pytest.fixture
def graph():
    """Graph built from the synthetic fixture."""
    return load_graph(TEST_GRAPH_PATH).graph


def test_public_source_predicate(graph):
    path = ["public-b", "service-c"]
    assert apply_filters(graph, path, (Filter.PUBLIC_SOURCE,), FilterContext()) is True
    assert apply_filters(graph, ["service-c", "sink-db"], (Filter.PUBLIC_SOURCE,), FilterContext()) is False


def test_sink_predicate(graph):
    path = ["public-b", "service-c", "sink-db"]
    assert apply_filters(graph, path, (Filter.SINK,), FilterContext()) is True
    assert apply_filters(graph, ["public-b", "service-c"], (Filter.SINK,), FilterContext()) is False


def test_sink_predicate_with_sink_kinds(graph):
    path = ["public-b", "service-c", "sink-db"]
    ctx = FilterContext(sink_kinds=frozenset({"rds"}))
    assert apply_filters(graph, path, (Filter.SINK,), ctx) is True

    ctx_sqs = FilterContext(sink_kinds=frozenset({"sqs"}))
    assert apply_filters(graph, path, (Filter.SINK,), ctx_sqs) is False


def test_vulnerable_predicate(graph):
    path = ["public-b", "service-c", "service-d"]
    assert apply_filters(graph, path, (Filter.VULNERABLE,), FilterContext()) is True
    assert apply_filters(graph, ["public-b", "service-c"], (Filter.VULNERABLE,), FilterContext()) is False


def test_combined_filters_and_semantics(graph):
    filters = (Filter.PUBLIC_SOURCE, Filter.SINK, Filter.VULNERABLE)

    path = ["public-b", "service-c", "service-d", "sink-queue"]
    assert apply_filters(graph, path, filters, FilterContext()) is True

    missing_vuln = ["public-b", "service-c", "sink-db"]
    assert apply_filters(graph, missing_vuln, filters, FilterContext()) is False
