"""PostgreSQL + pgvector ``VectorStore`` implementation.

Stores one embedding per entity id with the content hash that produced it, and
searches by cosine distance (the ``<=>`` operator). Requires a running Postgres
with the ``vector`` extension; it is exercised via integration/manual runs, while
offline unit tests use :class:`~threatweave.vector.memory.InMemoryVectorStore`.

This module is imported lazily by the vector factory, so code paths that never
select the pgvector backend do not touch the psycopg driver.
"""

from __future__ import annotations

from collections.abc import Sequence

import psycopg
from pgvector import Vector
from pgvector.psycopg import register_vector

from threatweave.vector.base import Neighbor, VectorStore

# Fixed identifier defined in code (never user input), safe to interpolate.
_TABLE = "entity_embeddings"


class PgVectorStore(VectorStore):
    """A ``VectorStore`` backed by Postgres/pgvector.

    Note: vector parameters must be wrapped in :class:`pgvector.Vector` —
    ``register_vector`` registers dumpers for ``Vector``/numpy arrays only, so a
    plain Python list would be sent as a Postgres array (``float8[]``), which the
    ``<=>`` operator rejects.
    """

    def __init__(self, dsn: str, dim: int) -> None:
        self._dim = dim
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._ensure_schema()
        register_vector(self._conn)

    def _ensure_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "entity_id text PRIMARY KEY, "
                "content_hash text, "
                f"embedding vector({self._dim}))"
            )

    def upsert(
        self, entity_id: str, vector: Sequence[float], *, content_hash: str | None = None
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {_TABLE} (entity_id, content_hash, embedding) "
                "VALUES (%s, %s, %s) "
                "ON CONFLICT (entity_id) DO UPDATE SET "
                "content_hash = EXCLUDED.content_hash, embedding = EXCLUDED.embedding",
                (entity_id, content_hash, Vector(list(vector))),
            )

    def has(self, entity_id: str, *, content_hash: str | None = None) -> bool:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT content_hash FROM {_TABLE} WHERE entity_id = %s", (entity_id,)
            )
            row = cur.fetchone()
        if row is None:
            return False
        if content_hash is None:
            return True
        return row[0] == content_hash

    def get(self, entity_id: str) -> list[float] | None:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT embedding FROM {_TABLE} WHERE entity_id = %s", (entity_id,)
            )
            row = cur.fetchone()
        return list(row[0]) if row is not None else None

    def search(
        self, vector: Sequence[float], *, k: int, exclude: str | None = None
    ) -> list[Neighbor]:
        query = Vector(list(vector))
        # Cosine similarity = 1 - cosine distance (the <=> operator).
        sql = f"SELECT entity_id, 1 - (embedding <=> %s) AS score FROM {_TABLE}"
        params: list[object] = [query]
        if exclude is not None:
            sql += " WHERE entity_id <> %s"
            params.append(exclude)
        # LIMIT must not be negative in Postgres; clamp like the memory backend.
        sql += " ORDER BY embedding <=> %s LIMIT %s"
        params.extend([query, max(k, 0)])

        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [Neighbor(id=row[0], score=float(row[1])) for row in rows]

    def close(self) -> None:
        self._conn.close()
