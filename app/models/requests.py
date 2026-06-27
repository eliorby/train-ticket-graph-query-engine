"""Request/query parameter models."""

from pydantic import BaseModel, Field


class GraphQueryParams(BaseModel):
    """Parsed query parameters for the graph endpoint."""

    filters: list[str] = Field(default_factory=list)
    max_depth: int = 10
    max_results: int = 500
    sink_kinds: list[str] | None = None
