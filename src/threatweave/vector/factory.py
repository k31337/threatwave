"""Vector store construction from configuration."""

from __future__ import annotations

from threatweave.config import Settings
from threatweave.vector.base import VectorStore
from threatweave.vector.memory import InMemoryVectorStore


def build_vector_store(settings: Settings) -> VectorStore | None:
    """Return the configured vector store, or ``None`` when semantic search is off.

    ``VECTOR_BACKEND=none`` (the default) yields ``None`` so callers keep the
    Phase 1/2 behaviour untouched.
    """
    backend = settings.vector_backend.lower()

    if backend == "none":
        return None
    if backend == "memory":
        return InMemoryVectorStore()
    if backend == "pgvector":
        # Imported lazily so the memory/none paths need no psycopg driver.
        from threatweave.vector.pgvector_store import PgVectorStore

        return PgVectorStore(dsn=settings.postgres.dsn, dim=settings.llm.embed_dim)

    raise ValueError(
        f"unknown VECTOR_BACKEND={settings.vector_backend!r}; "
        "use one of: none, memory, pgvector"
    )
