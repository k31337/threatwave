"""Graph storage layer.

``GraphStore`` is the port; ``InMemoryGraphStore`` and ``Neo4jGraphStore`` are
the adapters. Correlation logic depends only on the port, so tests run against
the in-memory backend without needing a live Neo4j.
"""

from threatweave.graph.base import GraphStore
from threatweave.graph.memory import InMemoryGraphStore

__all__ = ["GraphStore", "InMemoryGraphStore"]
