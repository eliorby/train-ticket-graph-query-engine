"""Unit tests for bounded path enumeration."""

from app.engine.enumerator import enumerate_routes
from app.engine.filters import FilterContext
from app.graph.loader import load_graph
from app.models.filters import Filter
from app.models.truncation import TruncationReason

from tests.conftest import TEST_GRAPH_PATH


NO_DFS_STEP_LIMIT_FOR_TESTS = 10_000

def test_enumerates_across_multiple_sources_and_sinks():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, truncated, truncation_reason = enumerate_routes(
        graph,
        (Filter.PUBLIC_SOURCE, Filter.SINK),
        FilterContext(),
        max_depth=10,
        max_results=100,
        max_dfs_steps=NO_DFS_STEP_LIMIT_FOR_TESTS,
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
    routes, _, _ = enumerate_routes(
        graph,
        (Filter.PUBLIC_SOURCE, Filter.SINK),
        FilterContext(),
        max_depth=2,
        max_results=100,
        max_dfs_steps=NO_DFS_STEP_LIMIT_FOR_TESTS,
    )
    assert routes
    assert all(route.length <= 2 for route in routes)
    shallow, _, _ = enumerate_routes(
        graph,
        (Filter.PUBLIC_SOURCE, Filter.SINK),
        FilterContext(),
        max_depth=10,
        max_results=100,
        max_dfs_steps=NO_DFS_STEP_LIMIT_FOR_TESTS,
    )
    assert len(shallow) >= len(routes)


def test_max_results_truncates():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, truncated, truncation_reason = enumerate_routes(
        graph,
        (Filter.SINK,),
        FilterContext(),
        max_depth=10,
        max_results=1,
        max_dfs_steps=NO_DFS_STEP_LIMIT_FOR_TESTS,
    )
    assert len(routes) == 1
    assert truncated is True


def test_cycle_edges_annotated_not_expanded():
    graph = load_graph(TEST_GRAPH_PATH).graph
    routes, _, _ = enumerate_routes(
        graph,
        (Filter.PUBLIC_SOURCE, Filter.VULNERABLE, Filter.SINK),
        FilterContext(),
        max_depth=10,
        max_results=100,
        max_dfs_steps=NO_DFS_STEP_LIMIT_FOR_TESTS,
    )
    cyclic = [route for route in routes if route.has_cycle_edges]
    assert cyclic
    route = cyclic[0]
    assert route.path.count("public-b") == 1
    assert any(
        edge.from_node == "service-d" and edge.to_node == "public-b"
        for edge in route.cycle_edges
    )

def test_max_dfs_steps_truncates_search():
    graph = load_graph(TEST_GRAPH_PATH).graph

    routes, truncated, truncation_reason = enumerate_routes(
        graph,
        (Filter.SINK,),
        FilterContext(),
        max_depth=10,
        max_results=100,
        max_dfs_steps=1,
    )

    assert truncated is True
    assert truncation_reason == TruncationReason.MAX_DFS_STEPS.value
