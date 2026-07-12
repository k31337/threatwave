"""FastAPI application exposing correlation queries over the threat graph."""

from threatweave.api.app import app, create_app

__all__ = ["app", "create_app"]
