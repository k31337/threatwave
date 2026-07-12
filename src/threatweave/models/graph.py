"""Graph value objects: nodes, edges and the subgraph returned by correlation.

These are transport/representation types decoupled from any storage backend, so
both the Neo4j and in-memory ``GraphStore`` implementations return the same
``Subgraph`` shape.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from threatweave.models.ioc import IOC


class RelationType(StrEnum):
    """Types of structural relationships between graph nodes.

    Relationships are asserted deterministically from source data — never
    inferred by an LLM.
    """

    RELATED_TO = "related_to"
    ATTRIBUTED_TO = "attributed_to"  # IOC/Campaign -> Actor
    PART_OF = "part_of"  # IOC -> Campaign, Campaign -> Actor
    RESOLVES_TO = "resolves_to"  # Domain -> IP
    COMMUNICATES_WITH = "communicates_with"  # IOC -> IOC
    USES = "uses"  # Campaign/Actor -> TTP
    TARGETS = "targets"  # Campaign/Actor -> Sector
    SEMANTIC_SIMILARITY = "semantic_similarity"  # Campaign <-> Campaign (by embedding)


class Node(BaseModel):
    """A node in the threat graph.

    ``id`` is a stable, deterministic key (see :func:`ioc_node_id`) so the same
    entity maps to the same node across ingestions.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    kind: str  # "ioc" | "actor" | "campaign"
    label: str


class Edge(BaseModel):
    """A directed relationship between two nodes, referenced by node id.

    ``score`` is set only for weighted relationships (semantic similarity carries
    its cosine score); structural edges leave it ``None``.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    type: RelationType
    score: float | None = None


class Subgraph(BaseModel):
    """A set of nodes and edges, e.g. the neighbourhood of a queried IOC."""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)


def ioc_node_id(ioc: IOC) -> str:
    """Return the canonical, deterministic node id for an IOC."""
    return f"ioc:{ioc.type.value}:{ioc.value}"


def actor_node_id(name: str) -> str:
    """Return the canonical node id for an actor."""
    return f"actor:{name}"


def campaign_node_id(name: str) -> str:
    """Return the canonical node id for a campaign."""
    return f"campaign:{name}"


def ttp_node_id(technique_id: str) -> str:
    """Return the canonical node id for a MITRE ATT&CK technique."""
    return f"ttp:{technique_id}"


def sector_node_id(canonical_name: str) -> str:
    """Return the canonical node id for a target sector.

    Expects an already-normalized name (see
    :func:`threatweave.models.normalize.normalize_sector`).
    """
    return f"sector:{canonical_name}"
