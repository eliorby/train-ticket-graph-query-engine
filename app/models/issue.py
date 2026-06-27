"""Validation issue model surfaced by graph integrity checks."""

from pydantic import BaseModel


class Issue(BaseModel):
    """A structural or data-integrity finding from graph validation."""

    code: str
    severity: str
    message: str
