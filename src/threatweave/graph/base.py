"""The ``GraphStore`` port: storage-agnostic threat graph operations."""

from __future__ import annotations

from abc import ABC, abstractmethod

from threatweave.models.graph import Node, RelationType, Subgraph
from threatweave.models.ioc import IOC, Actor, Campaign


class GraphStore(ABC):
    """Abstract interface to the threat graph.

    Writes are upserts keyed by deterministic node ids, so re-ingesting the same
    entity is idempotent. Reads expose a single traversal primitive,
    :meth:`neighborhood`, on top of which deterministic correlation is built.
    """

    # --- Writes (idempotent upserts) ---

    @abstractmethod
    def upsert_node(self, node: Node) -> Node:
        """Create or update ``node`` (keyed by its id) and return it.

        The generic primitive on which the typed helpers below are built; also
        used directly for kinds without a dedicated model (TTP, sector).
        """

    @abstractmethod
    def upsert_ioc(self, ioc: IOC) -> Node:
        """Create or update the node for ``ioc`` and return it."""

    @abstractmethod
    def upsert_actor(self, actor: Actor) -> Node:
        """Create or update the node for ``actor`` and return it."""

    @abstractmethod
    def upsert_campaign(self, campaign: Campaign) -> Node:
        """Create or update the node for ``campaign`` and return it."""

    @abstractmethod
    def add_edge(self, source_id: str, target_id: str, rel_type: RelationType) -> None:
        """Assert a directed relationship between two existing nodes.

        Both endpoints must already exist. Adding the same edge twice is a no-op.
        """

    # --- Reads ---

    @abstractmethod
    def get_node(self, node_id: str) -> Node | None:
        """Return the node with ``node_id``, or ``None`` if absent."""

    @abstractmethod
    def neighborhood(self, node_id: str, depth: int = 1) -> Subgraph:
        """Return the subgraph reachable from ``node_id`` within ``depth`` hops.

        Traversal is undirected (relationships are followed in both directions),
        which is what correlation needs: a shared actor or resolved IP links two
        indicators regardless of edge orientation. Returns an empty subgraph if
        the node does not exist.
        """

    # --- Lifecycle ---

    def close(self) -> None:  # noqa: B027 - intentional concrete no-op default
        """Release any underlying resources. No-op by default."""
