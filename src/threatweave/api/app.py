"""FastAPI application factory and lifespan wiring."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from threatweave.api.routes import router
from threatweave.config import Settings, get_settings
from threatweave.graph.base import GraphStore
from threatweave.graph.factory import build_store
from threatweave.ingest import ingest_otx_payload
from threatweave.vector.base import VectorStore
from threatweave.vector.factory import build_vector_store

logger = logging.getLogger(__name__)

_SAMPLE_PATH = Path("data/samples/otx_subscribed.json")


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
    try:
        yield
    finally:
        if owns_store:
            app.state.store.close()
        if owns_vector_store and app.state.vector_store is not None:
            app.state.vector_store.close()


def create_app(
    store: GraphStore | None = None, vector_store: VectorStore | None = None
) -> FastAPI:
    """Build the FastAPI app, optionally with a graph/vector store injected."""
    app = FastAPI(
        title="ThreatWeave",
        version="0.1.0",
        summary="Deterministic threat intelligence correlation graph.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.vector_store = vector_store
    app.include_router(router)
    return app


# Default application instance used by ``uvicorn threatweave.api.app:app``.
app = create_app()
