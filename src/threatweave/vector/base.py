"""The ``VectorStore`` port and its value types."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Neighbor:
    """A semantic neighbour: an entity id and its cosine similarity score."""

    id: str
    score: float


def content_hash(text: str) -> str:
    """Return a stable hash of ``text`` used to cache embeddings.

    Embeddings are recomputed only when the source text changes, so this hash is
    stored alongside each vector and compared on re-ingestion.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class VectorStore(ABC):
    """Abstract vector store keyed by entity id.

    Vectors are upserted (idempotent per id) and queried by cosine similarity.
    The ``content_hash`` carried with each vector powers the compute-once cache.
    """

    @abstractmethod
    def upsert(
        self, entity_id: str, vector: Sequence[float], *, content_hash: str | None = None
    ) -> None:
        """Insert or replace the vector for ``entity_id``."""

    @abstractmethod
    def has(self, entity_id: str, *, content_hash: str | None = None) -> bool:
        """Return whether a vector for ``entity_id`` exists.

        When ``content_hash`` is given, returns True only if the stored hash
        matches — i.e. the cached embedding is still current for that text.
        """

    @abstractmethod
    def get(self, entity_id: str) -> list[float] | None:
        """Return the stored vector for ``entity_id``, or ``None`` if absent."""

    @abstractmethod
    def search(
        self, vector: Sequence[float], *, k: int, exclude: str | None = None
    ) -> list[Neighbor]:
        """Return the ``k`` nearest entities to ``vector`` by cosine similarity.

        Results are sorted by descending score. ``exclude`` drops one id from the
        results (typically the query entity itself).
        """

    def close(self) -> None:  # noqa: B027 - intentional concrete no-op default
        """Release any underlying resources. No-op by default."""
