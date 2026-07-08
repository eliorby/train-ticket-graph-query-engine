"""API-level tests using FastAPI TestClient."""

from app.config import MAX_DEPTH_CEILING, MAX_RESULTS_CEILING, MAX_DFS_STEPS_CEILING
from app.models.filters import Filter
from app.models.issue import IssueCode

from tests.conftest import REAL_GRAPH_PATH, TEST_GRAPH_PATH


def test_get_graph_no_filters(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get("/graph")
    assert response.status_code == 200
    body = response.json()

    assert "graph" in body
    assert "nodes" in body["graph"] and "edges" in body["graph"]
    assert len(body["graph"]["nodes"]) == 8

    assert "summary" in body
    assert body["summary"]["node_count"] == 8
    assert "public-a" in body["summary"]["public_sources"]
    assert "public-b" in body["summary"]["public_sources"]
    assert "sink-db" in body["summary"]["sinks"]
    assert "sink-queue" in body["summary"]["sinks"]


def test_get_graph_filters_happy_path(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get(
        "/graph",
        params={
            "filters": f"{Filter.PUBLIC_SOURCE.value},{Filter.SINK.value}",
            "maxDepth": 10,
            "maxResults": 50,
            "maxDfsSteps": 10_000,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["graph"]["nodes"]
    assert body["truncated"] is False


def test_get_graph_unknown_filter(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get("/graph", params={"filters": "notARealFilter"})
    assert response.status_code == 400
    assert "Unknown filter" in response.json()["detail"]


def test_get_graph_clamps_max_results(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get(
        "/graph",
        params={"filters": Filter.SINK.value, "maxResults": 99999},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["max_results"] == MAX_RESULTS_CEILING


def test_get_graph_clamps_max_depth(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get(
        "/graph",
        params={"filters": Filter.SINK.value, "maxDepth": 99999},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["max_depth"] == MAX_DEPTH_CEILING


def test_get_graph_clamps_max_dfs_steps(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get(
        "/graph",
        params={"filters": Filter.SINK.value, "maxDfsSteps": 9999999},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["max_dfs_steps"] == MAX_DFS_STEPS_CEILING


def test_get_graph_validate(client_for_graph):
    client = client_for_graph(REAL_GRAPH_PATH)
    response = client.get("/graph/validate")
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert any(
        issue["code"] == IssueCode.DANGLING_NODE_REFERENCE.value
        and "assurance-service" in issue["message"]
        for issue in body["issues"]
    )


def test_get_filters(client_for_graph):
    client = client_for_graph(TEST_GRAPH_PATH)
    response = client.get("/filters")
    assert response.status_code == 200
    names = {item["name"] for item in response.json()["filters"]}
    assert names == {Filter.PUBLIC_SOURCE.value, Filter.SINK.value, Filter.VULNERABLE.value}
