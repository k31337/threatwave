"""FastAPI application factory and lifespan wiring."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from threatweave.api.routes import router
from threatweave.api.security import limiter
from threatweave.config import Settings, get_settings
from threatweave.graph.base import GraphStore
from threatweave.graph.factory import build_store
from threatweave.ingest import ingest_otx_payload
from threatweave.llm.base import LLMProvider
from threatweave.llm.factory import get_provider
from threatweave.vector.base import VectorStore
from threatweave.vector.factory import build_vector_store

logger = logging.getLogger(__name__)

_SAMPLE_PATH = Path("data/samples/otx_subscribed.json")
# Built single-page frontend, served by the API when present (see `frontend/`).
# Absent in dev (Vite serves it) and in CI; the API works fine without it.
_FRONTEND_DIST = Path("frontend/dist")


def _build_store(settings: Settings) -> GraphStore:
    """Construct the graph store and optionally seed it (memory backend demo)."""
    store = build_store(settings)
    if (
        settings.graph_backend == "memory"
        and settings.seed_sample
        and _SAMPLE_PATH.exists()
    ):
        payload = json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))
        ingest_otx_payload(store, payload)
        logger.info("seeded in-memory graph from %s", _SAMPLE_PATH)
    return store


def _build_provider(settings: Settings) -> LLMProvider | None:
    """Build the LLM provider, or ``None`` when none is configured.

    The narrative endpoint needs a provider; other endpoints do not, so a
    missing provider is not fatal — it just disables narration (503).
    """
    try:
        return get_provider(settings)
    except ValueError:
        logger.info("no LLM provider configured; narrative endpoint disabled")
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the graph store on startup and close it on shutdown.

    Any store/vector store injected via :func:`create_app` (as in tests) is used
    as-is and left for the caller to close.
    """
    settings = get_settings()
    owns_store = app.state.store is None
    if owns_store:
        app.state.store = _build_store(settings)
    owns_vector_store = app.state.vector_store is None
    if owns_vector_store:
        app.state.vector_store = build_vector_store(settings)
    if app.state.provider is None:
        app.state.provider = _build_provider(settings)
    try:
        yield
    finally:
        if owns_store:
            app.state.store.close()
        if owns_vector_store and app.state.vector_store is not None:
            app.state.vector_store.close()


def create_app(
    store: GraphStore | None = None,
    vector_store: VectorStore | None = None,
    provider: LLMProvider | None = None,
) -> FastAPI:
    """Build the FastAPI app, optionally with stores/provider injected."""
    app = FastAPI(
        title="ThreatWeave",
        version="0.1.0",
        summary="Deterministic threat intelligence correlation graph.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.vector_store = vector_store
    app.state.provider = provider

    # Rate limiting (slowapi): the limiter must live on app.state, and 429s are
    # turned into a JSON response by the shared handler.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.include_router(router)
    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built SPA at ``/`` when a production build is present.

    Mounted *after* the API router so ``/health`` and ``/api/*`` keep priority;
    the catch-all only handles the remaining paths. ``html=True`` serves
    ``index.html`` for unknown paths, which is what a client-side-routed SPA
    needs. When ``frontend/dist`` is absent (dev, tests, CI) this is a no-op.
    """
    if _FRONTEND_DIST.is_dir():
        app.mount(
            "/", StaticFiles(directory=_FRONTEND_DIST, html=True), name="frontend"
        )
        logger.info("serving frontend from %s", _FRONTEND_DIST)


# Default application instance used by ``uvicorn threatweave.api.app:app``.
app = create_app()
