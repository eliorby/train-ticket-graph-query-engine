"""Filter discovery endpoint."""

from fastapi import APIRouter

from app.engine.filters import get_filter_info
from app.models.api.filters import FiltersResponse, FilterInfo


router = APIRouter(tags=["filters"])


@router.get("/filters", response_model=FiltersResponse)
def get_available_filters() -> FiltersResponse:
    """Return self-describing metadata for all registered filters."""
    return FiltersResponse(
        filters=[
            FilterInfo(
                name=definition.name,
                scope=definition.scope.value,
                description=definition.description,
                parameters=list(definition.parameters),
            )
            for definition in get_filter_info()
        ]
    )
