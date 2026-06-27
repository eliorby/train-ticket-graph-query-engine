"""Filter discovery endpoint."""

from fastapi import APIRouter

from app.engine.filters import get_filter_info
from app.models.responses import FilterInfo, FiltersResponse

router = APIRouter(tags=["filters"])


@router.get("/filters", response_model=FiltersResponse)
def list_filters() -> FiltersResponse:
    """Return self-describing metadata for all registered filters."""
    filters = [
        FilterInfo(
            name=definition.name,
            scope=definition.scope,
            description=definition.description,
            parameters=list(definition.parameters),
        )
        for definition in get_filter_info()
    ]
    return FiltersResponse(filters=filters)
