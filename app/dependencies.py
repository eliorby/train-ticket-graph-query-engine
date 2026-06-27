"""FastAPI dependency providers."""

from __future__ import annotations

from fastapi import Request

from app.state import AppState


def get_app_state(request: Request) -> AppState:
    """Return the application state attached during startup."""
    return request.app.state.app_state
