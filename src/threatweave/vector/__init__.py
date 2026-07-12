"""Vector storage layer for semantic similarity.

``VectorStore`` is the port; ``InMemoryVectorStore`` and ``PgVectorStore`` are the
adapters, mirroring the graph layer. Similarity search uses cosine similarity.
"""

from threatweave.vector.base import Neighbor, VectorStore, content_hash
from threatweave.vector.memory import InMemoryVectorStore

__all__ = ["VectorStore", "Neighbor", "content_hash", "InMemoryVectorStore"]
