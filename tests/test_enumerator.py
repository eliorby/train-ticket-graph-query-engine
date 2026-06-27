"""Unit tests for bounded path enumeration."""

from app.engine.enumerator import enumerate_routes
from app.engine.filters import FilterContext
from app.graph.loader import load_graph
from tests.conftest import TEST_GRAPH_PATH


def test_enumerates_across_multiple_sources_and_sinks():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, truncated = enumerate_routes(
        graph,
        ["publicSource", "sink"],
        FilterContext(),
        max_depth=10,
        max_results=100,
    )
    assert routes

    sources_seen = {route.path[0] for route in routes}
    sinks_seen = {route.path[-1] for route in routes}

    assert sources_seen == {"public-a", "public-b"}
    assert sinks_seen == {"sink-db", "sink-queue"}
    assert all(graph.is_public_source(s) for s in sources_seen)
    assert all(graph.is_sink(s) for s in sinks_seen)
    assert not truncated

    # public-a only ever reaches sink-queue, never sink-db — confirms the
    # cross-product isn't faked/padded by assuming every source reaches
    # every sink
    public_a_sinks = {r.path[-1] for r in routes if r.path[0] == "public-a"}
    assert public_a_sinks == {"sink-queue"}


def test_max_depth_limits_hops():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, _ = enumerate_routes(
        graph,
        ["publicSource", "sink"],
        FilterContext(),
        max_depth=2,
        max_results=100,
    )
    assert routes
    assert all(route.length <= 2 for route in routes)
    shallow, _ = enumerate_routes(
        graph,
        ["publicSource", "sink"],
        FilterContext(),
        max_depth=10,
        max_results=100,
    )
    assert len(shallow) >= len(routes)


def test_max_results_truncates():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, truncated = enumerate_routes(
        graph,
        ["sink"],
        FilterContext(),
        max_depth=10,
        max_results=1,
    )
    assert len(routes) == 1
    assert truncated is True


def test_cycle_edges_annotated_not_expanded():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, _ = enumerate_routes(
        graph,
        ["publicSource", "vulnerable", "sink"],
        FilterContext(),
        max_depth=10,
        max_results=100,
    )
    cyclic = [route for route in routes if route.has_cycle_edges]
    assert cyclic
    route = cyclic[0]
    assert route.path.count("public-b") == 1
    assert any(
        edge.from_node == "service-d" and edge.to_node == "public-b"
        for edge in route.cycle_edges
    )
