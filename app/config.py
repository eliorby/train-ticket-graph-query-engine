"""Application configuration loaded from environment variables."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GRAPH_DATA_PATH: Path = Path(
    os.environ.get("GRAPH_DATA_PATH", PROJECT_ROOT / "train-ticket-be.json")
)

DEFAULT_MAX_DEPTH: int = 10
MAX_DEPTH_CEILING: int = 20

DEFAULT_MAX_RESULTS: int = 500
MAX_RESULTS_CEILING: int = 1_000

DEFAULT_MAX_DFS_STEPS: int = 10_000
MAX_DFS_STEPS_CEILING: int = 100_000
