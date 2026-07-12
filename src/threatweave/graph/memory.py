"""In-memory ``GraphStore`` implementation for tests and local experiments.

Backed by plain dictionaries and sets. It has no persistence and is not
thread-safe, but it implements exactly the same contract as the Neo4j backend,
so correlation logic can be tested without a database.
"""

from __future__ import annotations

from collections import defaultdict

from threatweave.graph.base import GraphStore
from threatweave.models.graph import (
    Edge,
    Node,
    RelationType,
    Subgraph,
    actor_node_id,
    campaign_node_id,
    ioc_node_id,
)
from threatweave.models.ioc import IOC, Actor, Campaign


class InMemoryGraphStore(GraphStore):
    """A dictionary-backed threat graph."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: set[Edge] = set()
        # Undirected adjacency for traversal.
        self._adjacency: dict[str, set[str]] = defaultdict(set)

    def _upsert(self, node: Node) -> Node:
        self._nodes[node.id] = node
        return node

    def upsert_ioc(self, ioc: IOC) -> Node:
        return self._upsert(Node(id=ioc_node_id(ioc), kind="ioc", label=ioc.value))

    def upsert_actor(self, actor: Actor) -> Node:
        return self._upsert(
            Node(id=actor_node_id(actor.name), kind="actor", label=actor.name)
        )

    def upsert_campaign(self, campaign: Campaign) -> Node:
        return self._upsert(
            Node(id=campaign_node_id(campaign.name), kind="campaign", label=campaign.name)
        )

    def add_edge(self, source_id: str, target_id: str, rel_type: RelationType) -> None:
        for node_id in (source_id, target_id):
            if node_id not in self._nodes:
                raise KeyError(f"unknown node: {node_id!r}")
        self._edges.add(Edge(source=source_id, target=target_id, type=rel_type))
        self._adjacency[source_id].add(target_id)
        self._adjacency[target_id].add(source_id)

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def neighborhood(self, node_id: str, depth: int = 1) -> Subgraph:
        if node_id not in self._nodes:
            return Subgraph()

        # Breadth-first expansion up to ``depth`` hops.
        visited: set[str] = {node_id}
        frontier: set[str] = {node_id}
        for _ in range(max(depth, 0)):
            next_frontier: set[str] = set()
            for current in frontier:
                next_frontier |= self._adjacency[current] - visited
            if not next_frontier:
                break
            visited |= next_frontier
            frontier = next_frontier

        nodes = sorted(
            (self._nodes[i] for i in visited), key=lambda node: node.id
        )
        edges = sorted(
            (
                edge
                for edge in self._edges
                if edge.source in visited and edge.target in visited
            ),
            key=lambda edge: (edge.source, edge.target, edge.type.value),
        )
        return Subgraph(nodes=nodes, edges=edges)
