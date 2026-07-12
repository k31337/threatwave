"""Deterministic IOC correlation, optionally augmented with semantic similarity.

Structural correlation is pure graph logic: resolve the queried indicator to a
node and return its neighbourhood — a traversal, not an inference. When a vector
store is supplied, the result is *augmented* (never replaced) with
``semantic_similarity`` edges linking the queried indicator's campaign(s) to
other campaigns whose embeddings are close, surfacing relationships that share no
exact IOC.
"""

from __future__ import annotations

from threatweave.correlation.similar import similar
from threatweave.graph.base import GraphStore
from threatweave.models.graph import Edge, RelationType, Subgraph, ioc_node_id
from threatweave.parsers.ioc_parser import parse_iocs
from threatweave.vector.base import VectorStore


def correlate(
    store: GraphStore,
    ioc: str,
    *,
    depth: int = 1,
    vector_store: VectorStore | None = None,
    k: int = 5,
    min_score: float = 0.0,
) -> Subgraph:
    """Return the subgraph of relationships around a queried indicator.

    The raw ``ioc`` string is parsed to determine its type(s) and canonical
    form, then resolved against the store. When the input yields several
    candidate types (e.g. a URL also contains a domain), the most specific match
    — the longest indicator value — is tried first.

    Args:
        store: The graph store to query.
        ioc: The indicator value to correlate (e.g. an IP, domain, hash or URL).
        depth: How many relationship hops to include (default 1).
        vector_store: Optional vector store; when given, semantic-similarity
            edges are added for the campaigns in the structural result.
        k: Max semantic neighbours per campaign.
        min_score: Minimum cosine score for a semantic edge.

    Returns:
        The neighbourhood :class:`Subgraph`, or an empty one if the indicator is
        not present in the graph.
    """
    candidates = sorted(parse_iocs(ioc), key=lambda parsed: len(parsed.value), reverse=True)
    subgraph = Subgraph()
    for candidate in candidates:
        node_id = ioc_node_id(candidate)
        if store.get_node(node_id) is not None:
            subgraph = store.neighborhood(node_id, depth=depth)
            break

    if vector_store is not None and subgraph.nodes:
        subgraph = _augment_with_semantic(subgraph, store, vector_store, k, min_score)
    return subgraph


def _augment_with_semantic(
    subgraph: Subgraph,
    store: GraphStore,
    vector_store: VectorStore,
    k: int,
    min_score: float,
) -> Subgraph:
    """Add ``semantic_similarity`` edges (and any new campaign nodes) to a subgraph."""
    nodes = {node.id: node for node in subgraph.nodes}
    edges = list(subgraph.edges)
    edge_keys = {(edge.source, edge.target, edge.type) for edge in edges}

    # Only campaigns carry embeddings, so semantic links anchor on them.
    campaign_ids = [node.id for node in subgraph.nodes if node.kind == "campaign"]
    for campaign_id in campaign_ids:
        for neighbor in similar(vector_store, campaign_id, k=k, min_score=min_score):
            if neighbor.id == campaign_id:
                continue
            if neighbor.id not in nodes:
                node = store.get_node(neighbor.id)
                if node is None:
                    continue  # vector present but node missing from the graph
                nodes[neighbor.id] = node
            key = (campaign_id, neighbor.id, RelationType.SEMANTIC_SIMILARITY)
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(
                    Edge(
                        source=campaign_id,
                        target=neighbor.id,
                        type=RelationType.SEMANTIC_SIMILARITY,
                        score=neighbor.score,
                    )
                )

    sorted_nodes = sorted(nodes.values(), key=lambda node: node.id)
    sorted_edges = sorted(
        edges, key=lambda edge: (edge.source, edge.target, edge.type.value)
    )
    return Subgraph(nodes=sorted_nodes, edges=sorted_edges)
