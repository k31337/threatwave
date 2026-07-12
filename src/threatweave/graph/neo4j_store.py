"""Neo4j-backed ``GraphStore`` implementation.

Nodes are MERGEd on their deterministic ``id`` so ingestion is idempotent.
Relationships use a single ``LINKED`` type carrying the semantic ``RelationType``
as a property, which keeps the write path parameterizable (Cypher does not allow
parameterized relationship types or labels).

This backend requires a running Neo4j instance and is therefore exercised via
integration testing / manual runs rather than the offline unit tests, which use
:class:`~threatweave.graph.memory.InMemoryGraphStore`.
"""

from __future__ import annotations

from neo4j import GraphDatabase

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

# Fixed Cypher labels per node kind. Chosen from a closed set in code (never from
# user input), so interpolating them into query strings is safe.
_KIND_LABELS: dict[str, str] = {
    "ioc": "IOC",
    "actor": "Actor",
    "campaign": "Campaign",
}


class Neo4jGraphStore(GraphStore):
    """A ``GraphStore`` backed by Neo4j via the Bolt driver."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    # --- Writes ---

    def _merge_node(self, node: Node) -> Node:
        neo_label = _KIND_LABELS[node.kind]
        # ``neo_label`` comes from the closed ``_KIND_LABELS`` map, not user input.
        query = (
            f"MERGE (n:{neo_label} {{id: $id}}) "
            "SET n.kind = $kind, n.label = $label"
        )
        with self._driver.session() as session:
            session.run(query, id=node.id, kind=node.kind, label=node.label)
        return node

    def upsert_ioc(self, ioc: IOC) -> Node:
        return self._merge_node(Node(id=ioc_node_id(ioc), kind="ioc", label=ioc.value))

    def upsert_actor(self, actor: Actor) -> Node:
        return self._merge_node(
            Node(id=actor_node_id(actor.name), kind="actor", label=actor.name)
        )

    def upsert_campaign(self, campaign: Campaign) -> Node:
        return self._merge_node(
            Node(id=campaign_node_id(campaign.name), kind="campaign", label=campaign.name)
        )

    def add_edge(self, source_id: str, target_id: str, rel_type: RelationType) -> None:
        query = (
            "MATCH (a {id: $source}), (b {id: $target}) "
            "MERGE (a)-[r:LINKED {type: $type}]->(b)"
        )
        with self._driver.session() as session:
            result = session.run(
                query, source=source_id, target=target_id, type=rel_type.value
            )
            summary = result.consume()
            # MATCH found neither endpoint => nothing was created or matched.
            if summary.counters.relationships_created == 0 and not self._edge_exists(
                source_id, target_id, rel_type
            ):
                raise KeyError(
                    f"cannot link unknown nodes: {source_id!r} -> {target_id!r}"
                )

    def _edge_exists(
        self, source_id: str, target_id: str, rel_type: RelationType
    ) -> bool:
        query = (
            "MATCH (a {id: $source})-[r:LINKED {type: $type}]->(b {id: $target}) "
            "RETURN count(r) AS n"
        )
        with self._driver.session() as session:
            record = session.run(
                query, source=source_id, target=target_id, type=rel_type.value
            ).single()
        return bool(record and record["n"] > 0)

    # --- Reads ---

    def get_node(self, node_id: str) -> Node | None:
        query = "MATCH (n {id: $id}) RETURN n.id AS id, n.kind AS kind, n.label AS label"
        with self._driver.session() as session:
            record = session.run(query, id=node_id).single()
        if record is None:
            return None
        return Node(id=record["id"], kind=record["kind"], label=record["label"])

    def neighborhood(self, node_id: str, depth: int = 1) -> Subgraph:
        # ``depth`` bounds a variable-length pattern; Cypher requires a literal
        # upper bound, so it is coerced to a non-negative int and interpolated.
        hops = max(int(depth), 0)
        if hops == 0:
            node = self.get_node(node_id)
            return Subgraph(nodes=[node]) if node is not None else Subgraph()
        query = f"""
        MATCH (start {{id: $id}})
        OPTIONAL MATCH (start)-[*1..{hops}]-(other)
        WITH start, collect(DISTINCT other) AS others
        WITH [start] + [n IN others WHERE n IS NOT NULL] AS nodes
        UNWIND nodes AS a
        UNWIND nodes AS b
        OPTIONAL MATCH (a)-[r:LINKED]->(b)
        RETURN
            collect(DISTINCT {{id: a.id, kind: a.kind, label: a.label}}) AS node_rows,
            collect(DISTINCT
                CASE WHEN r IS NULL THEN NULL
                ELSE {{source: a.id, target: b.id, type: r.type}} END
            ) AS edge_rows
        """
        with self._driver.session() as session:
            record = session.run(query, id=node_id).single()

        if record is None:
            return Subgraph()

        nodes = [
            Node(id=row["id"], kind=row["kind"], label=row["label"])
            for row in record["node_rows"]
        ]
        edges = [
            Edge(source=row["source"], target=row["target"], type=RelationType(row["type"]))
            for row in record["edge_rows"]
            if row is not None
        ]
        nodes.sort(key=lambda node: node.id)
        edges.sort(key=lambda edge: (edge.source, edge.target, edge.type.value))
        return Subgraph(nodes=nodes, edges=edges)
