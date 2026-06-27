"""Shared pytest fixtures."""

from __future__ import annotations

import importlib
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST_GRAPH_PATH = FIXTURES_DIR / "test-graph.json"
REAL_GRAPH_PATH = Path(__file__).resolve().parent.parent / "train-ticket-be.json"


@pytest.fixture
def test_graph_path() -> Path:
    """Path to the synthetic test fixture graph."""
    return TEST_GRAPH_PATH


@pytest.fixture
def real_graph_path() -> Path:
    """Path to the provided train-ticket graph."""
    return REAL_GRAPH_PATH


@pytest.fixture
def loaded_test_graph(test_graph_path: Path):
    """Load the synthetic fixture graph without starting the API."""
    from app.graph.loader import load_graph

    return load_graph(test_graph_path)


@pytest.fixture
def loaded_real_graph(real_graph_path: Path):
    """Load the real train-ticket graph without starting the API."""
    from app.graph.loader import load_graph

    return load_graph(real_graph_path)


@pytest.fixture
def client_for_graph(monkeypatch: pytest.MonkeyPatch) -> Generator:
    """Build a TestClient whose lifespan loads graph data from a given path."""
    active_clients: list[TestClient] = []

    def _make_client(graph_path: Path) -> TestClient:
        monkeypatch.setenv("GRAPH_DATA_PATH", str(graph_path))
        import app.config
        import app.main

        importlib.reload(app.config)
        importlib.reload(app.main)
        client = TestClient(app.main.app)
        client.__enter__()
        active_clients.append(client)
        return client

    yield _make_client

    for client in active_clients:
        client.__exit__(None, None, None)
