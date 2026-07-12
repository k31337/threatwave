"""Semantic nearest-neighbour search over the vector store.

This is the semantic complement to structural correlation: it finds entities
whose embeddings are close, i.e. reports/campaigns that read alike even when they
share no exact IOC. It ranks by cosine similarity — no LLM call at query time.
"""

from __future__ import annotations

from threatweave.vector.base import Neighbor, VectorStore


def similar(
    vector_store: VectorStore,
    entity_id: str,
    *,
    k: int = 5,
    min_score: float = 0.0,
) -> list[Neighbor]:
    """Return the ``k`` entities most semantically similar to ``entity_id``.

    Args:
        vector_store: The store to query.
        entity_id: The entity whose embedding anchors the search.
        k: Maximum number of neighbours to return.
        min_score: Drop neighbours below this cosine similarity.

    Returns:
        Neighbours sorted by descending score, excluding the entity itself.
        Empty if the entity has no stored embedding.
    """
    vector = vector_store.get(entity_id)
    if vector is None:
        return []
    neighbors = vector_store.search(vector, k=k, exclude=entity_id)
    return [neighbor for neighbor in neighbors if neighbor.score >= min_score]
