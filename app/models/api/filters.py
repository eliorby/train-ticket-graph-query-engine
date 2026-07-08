from typing import Any

from pydantic import BaseModel, Field

from app.models.filters import Filter


class FilterInfo(BaseModel):
    """Self-describing metadata for a registered filter predicate."""

    name: Filter
    scope: str
    description: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)


class FiltersResponse(BaseModel):
    """List of available route filters."""

    filters: list[FilterInfo]
