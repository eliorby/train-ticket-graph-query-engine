"""Graph validation endpoint."""

from fastapi import APIRouter, Depends

from app.dependencies import get_app_state
from app.engine.validators import run_validators
from app.models.responses import GraphValidateResponse, IssueResponse
from app.state import AppState

router = APIRouter(tags=["graph"])


@router.get("/graph/validate", response_model=GraphValidateResponse)
def validate_graph(state: AppState = Depends(get_app_state)) -> GraphValidateResponse:
    """Return structural integrity findings from the validator registry."""
    issues = run_validators(state.graph, state.load_issues)
    has_errors = any(issue.severity == "error" for issue in issues)
    return GraphValidateResponse(
        issues=[IssueResponse(**issue.model_dump()) for issue in issues],
        valid=not has_errors,
    )
