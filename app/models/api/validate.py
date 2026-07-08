"""Validation endpoint response schemas."""

from pydantic import BaseModel

from app.models.issue import Issue


class GraphValidateResponse(BaseModel):
    """Structural integrity report from validator registry."""

    issues: list[Issue]
    valid: bool