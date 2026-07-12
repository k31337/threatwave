"""Glue between ingestion connectors and the graph store.

Turns a structured OTX payload into graph nodes and edges. Each pulse becomes a
Campaign node, and every indicator in that pulse is linked to it with a
``PART_OF`` relationship. This is the deterministic source of correlation: two
indicators sharing a pulse are connected through their common campaign, so
querying one surfaces the other.
"""

from __future__ import annotations

import logging
from typing import Any

from threatweave.connectors.otx import normalize_indicators
from threatweave.graph.base import GraphStore
from threatweave.models.graph import RelationType
from threatweave.models.ioc import Campaign

logger = logging.getLogger(__name__)


def ingest_otx_payload(
    store: GraphStore, payload: dict[str, Any], *, source: str = "alienvault-otx"
) -> int:
    """Ingest a raw OTX pulses payload into ``store``.

    Args:
        store: Destination graph store.
        payload: Parsed OTX pulses response.
        source: Provenance label stamped on ingested IOCs.

    Returns:
        The number of IOC nodes written (counting each indicator once per pulse).
    """
    written = 0
    for pulse in payload.get("results", []):
        campaign_name = pulse.get("name") or pulse.get("id")
        campaign_node = (
            store.upsert_campaign(Campaign(name=campaign_name)) if campaign_name else None
        )

        # Reuse the connector's normalization on this single pulse.
        for ioc in normalize_indicators({"results": [pulse]}, source=source):
            ioc_node = store.upsert_ioc(ioc)
            if campaign_node is not None:
                store.add_edge(ioc_node.id, campaign_node.id, RelationType.PART_OF)
            written += 1

    logger.info("ingested %d IOC nodes from OTX payload", written)
    return written
