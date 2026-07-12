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
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_otx_payload

logger = logging.getLogger(__name__)

_SAMPLE_PATH = Path("data/samples/otx_subscribed.json")


def _build_store(settings: Settings) -> GraphStore:
    """Construct the graph store selected by configuration."""
    if settings.graph_backend == "memory":
        store = InMemoryGraphStore()
        if settings.seed_sample and _SAMPLE_PATH.exists():
            payload = json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))
            ingest_otx_payload(store, payload)
            logger.info("seeded in-memory graph from %s", _SAMPLE_PATH)
        return store

    # Imported lazily so the memory backend needs no database driver at hand.
    from threatweave.graph.neo4j_store import Neo4jGraphStore

    return Neo4jGraphStore(
        uri=settings.neo4j.uri,
        user=settings.neo4j.user,
        password=settings.neo4j.password,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the graph store on startup and close it on shutdown.

    If a store was injected via :func:`create_app` (as in tests), it is used
    as-is and left for the caller to close.
    """
    owns_store = app.state.store is None
    if owns_store:
        app.state.store = _build_store(get_settings())
    try:
        yield
    finally:
        if owns_store:
            app.state.store.close()


def create_app(store: GraphStore | None = None) -> FastAPI:
    """Build the FastAPI app, optionally with a pre-built graph store injected."""
    app = FastAPI(
        title="ThreatWeave",
        version="0.1.0",
        summary="Deterministic threat intelligence correlation graph.",
        lifespan=lifespan,
    )
    app.state.store = store
    app.include_router(router)
    return app


# Default application instance used by ``uvicorn threatweave.api.app:app``.
app = create_app()
