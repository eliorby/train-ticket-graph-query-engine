"""FastAPI application assembly and startup wiring."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import filters, graph, validate
from app.config import GRAPH_DATA_PATH
from app.graph.loader import load_graph
from app.state import AppState


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the graph once at startup and attach it to application state."""
    result = load_graph(GRAPH_DATA_PATH)
    app.state.app_state = AppState(graph=result.graph, load_issues=result.issues)
    yield


app = FastAPI(
    title="Train Ticket Graph Query Engine",
    description=(
        "Load a service-dependency graph and query bounded multi-hop routes "
        "with composable security filters."
    ),
    lifespan=lifespan,
)

app.include_router(graph.router)
app.include_router(validate.router)
app.include_router(filters.router)
