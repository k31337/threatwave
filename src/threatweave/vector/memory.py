"""In-memory ``VectorStore`` for tests and single-process demos.

Cosine similarity is computed in pure Python (no numpy dependency). Suitable for
small volumes; the pgvector backend handles scale and persistence.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from threatweave.vector.base import Neighbor, VectorStore


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Return the cosine similarity of two equal-length vectors (0.0 if degenerate)."""
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


class InMemoryVectorStore(VectorStore):
    """A dictionary-backed vector store."""

    def __init__(self) -> None:
        self._vectors: dict[str, list[float]] = {}
        self._hashes: dict[str, str | None] = {}

    def upsert(
        self, entity_id: str, vector: Sequence[float], *, content_hash: str | None = None
    ) -> None:
        self._vectors[entity_id] = list(vector)
        self._hashes[entity_id] = content_hash

    def has(self, entity_id: str, *, content_hash: str | None = None) -> bool:
        if entity_id not in self._vectors:
            return False
        if content_hash is None:
            return True
        return self._hashes.get(entity_id) == content_hash

    def get(self, entity_id: str) -> list[float] | None:
        return self._vectors.get(entity_id)

    def search(
        self, vector: Sequence[float], *, k: int, exclude: str | None = None
    ) -> list[Neighbor]:
        query = list(vector)
        scored = [
            Neighbor(id=entity_id, score=_cosine(query, stored))
            for entity_id, stored in self._vectors.items()
            if entity_id != exclude
        ]
        # Descending score; id as a stable tie-breaker for deterministic output.
        scored.sort(key=lambda neighbor: (-neighbor.score, neighbor.id))
        return scored[: max(k, 0)]
