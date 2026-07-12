"""Deterministic IOC correlation.

Correlation is pure graph logic: resolve the queried indicator to a node and
return its neighbourhood. No AI is involved — this is a traversal, not an
inference. The reserved semantic (embedding-based) correlation of a later phase
will augment, never replace, these exact-match results.
"""

from __future__ import annotations

from threatweave.graph.base import GraphStore
from threatweave.models.graph import Subgraph, ioc_node_id
from threatweave.parsers.ioc_parser import parse_iocs


def correlate(store: GraphStore, ioc: str, *, depth: int = 1) -> Subgraph:
    """Return the subgraph of relationships around a queried indicator.

    The raw ``ioc`` string is parsed to determine its type(s) and canonical
    form, then resolved against the store. When the input yields several
    candidate types (e.g. a URL also contains a domain), the most specific match
    — the longest indicator value — is tried first.

    Args:
        store: The graph store to query.
        ioc: The indicator value to correlate (e.g. an IP, domain, hash or URL).
        depth: How many relationship hops to include (default 1).

    Returns:
        The neighbourhood :class:`Subgraph`, or an empty one if the indicator is
        not present in the graph.
    """
    candidates = sorted(parse_iocs(ioc), key=lambda parsed: len(parsed.value), reverse=True)
    for candidate in candidates:
        node_id = ioc_node_id(candidate)
        if store.get_node(node_id) is not None:
            return store.neighborhood(node_id, depth=depth)
    return Subgraph()
