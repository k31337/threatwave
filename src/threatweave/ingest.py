"""Glue between ingestion connectors and the graph store.

Turns ingested intelligence into graph nodes and edges. For both OTX pulses and
free-text documents, a Campaign node is the hub: indicators, TTPs, the actor and
the targeted sectors all link to it. This is the deterministic source of
correlation — entities sharing a campaign are connected, so querying one surfaces
the others.
"""

from __future__ import annotations

import logging
from typing import Any

from threatweave.connectors.document import DocumentIntel
from threatweave.connectors.otx import normalize_indicators
from threatweave.graph.base import GraphStore
from threatweave.llm.base import LLMProvider
from threatweave.models.graph import (
    Node,
    RelationType,
    campaign_node_id,
    sector_node_id,
    ttp_node_id,
)
from threatweave.models.ioc import Actor, Campaign
from threatweave.models.normalize import normalize_sector, sector_display
from threatweave.vector.base import VectorStore, content_hash

logger = logging.getLogger(__name__)


def _embed_and_cache(
    vector_store: VectorStore | None,
    provider: LLMProvider | None,
    entity_id: str,
    text: str,
) -> None:
    """Embed ``text`` for ``entity_id`` and store it, skipping cached vectors.

    Does nothing unless both a provider and a vector store are supplied. The
    embedding is computed at most once per (entity, text) thanks to the content
    hash — re-ingesting unchanged text spends no tokens.
    """
    if vector_store is None or provider is None or not text.strip():
        return
    text_hash = content_hash(text)
    if vector_store.has(entity_id, content_hash=text_hash):
        logger.debug("embedding cache hit for %s", entity_id)
        return
    vector = provider.embed([text])[0]
    vector_store.upsert(entity_id, vector, content_hash=text_hash)
    logger.info("stored embedding for %s", entity_id)


def ingest_otx_payload(
    store: GraphStore,
    payload: dict[str, Any],
    *,
    source: str = "alienvault-otx",
    provider: LLMProvider | None = None,
    vector_store: VectorStore | None = None,
) -> int:
    """Ingest a raw OTX pulses payload into ``store``.

    Args:
        store: Destination graph store.
        payload: Parsed OTX pulses response.
        source: Provenance label stamped on ingested IOCs.
        provider: Optional LLM provider; when given with ``vector_store``, each
            pulse's descriptive text is embedded for semantic similarity.
        vector_store: Optional vector store for embeddings.

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

        if campaign_node is not None:
            # Embed the pulse's descriptive text (name + description if present).
            pulse_text = "\n".join(
                part for part in (pulse.get("name"), pulse.get("description")) if part
            )
            _embed_and_cache(vector_store, provider, campaign_node.id, pulse_text)

    logger.info("ingested %d IOC nodes from OTX payload", written)
    return written


def ingest_document(
    store: GraphStore,
    intel: DocumentIntel,
    *,
    provider: LLMProvider | None = None,
    vector_store: VectorStore | None = None,
) -> Node:
    """Ingest a document's extracted intelligence into ``store``.

    Creates a Campaign node for the report and links, all through it:
    IOCs (``PART_OF``), the actor (``ATTRIBUTED_TO``), TTPs (``USES``) and
    normalized target sectors (``TARGETS``). When ``provider`` and
    ``vector_store`` are supplied, the document text is embedded (once, cached)
    and stored under the campaign id for semantic similarity. Returns the
    campaign node.
    """
    campaign = store.upsert_campaign(Campaign(name=intel.report_name))

    if intel.extraction.actor:
        actor = store.upsert_actor(Actor(name=intel.extraction.actor))
        store.add_edge(campaign.id, actor.id, RelationType.ATTRIBUTED_TO)

    for ttp in intel.extraction.ttps:
        ttp_node = store.upsert_node(
            Node(
                id=ttp_node_id(ttp.technique_id),
                kind="ttp",
                label=ttp.name or ttp.technique_id,
            )
        )
        store.add_edge(campaign.id, ttp_node.id, RelationType.USES)

    # Normalize sectors so different wordings collapse onto one node.
    seen_sectors: set[str] = set()
    for raw_sector in intel.extraction.target_sectors:
        canonical = normalize_sector(raw_sector)
        if not canonical or canonical in seen_sectors:
            continue
        seen_sectors.add(canonical)
        sector_node = store.upsert_node(
            Node(
                id=sector_node_id(canonical),
                kind="sector",
                label=sector_display(canonical),
            )
        )
        store.add_edge(campaign.id, sector_node.id, RelationType.TARGETS)

    for ioc in intel.iocs:
        ioc_node = store.upsert_ioc(ioc)
        store.add_edge(ioc_node.id, campaign.id, RelationType.PART_OF)

    # Embed the document text under the campaign id for semantic similarity.
    _embed_and_cache(vector_store, provider, campaign.id, intel.text)

    logger.info(
        "ingested document %r: %d IOCs, %d TTPs, %d sectors, actor=%s",
        intel.report_name,
        len(intel.iocs),
        len(intel.extraction.ttps),
        len(seen_sectors),
        intel.extraction.actor or "-",
    )
    return campaign


# ``campaign_node_id`` is re-exported for callers that need the hub id.
__all__ = ["ingest_otx_payload", "ingest_document", "campaign_node_id"]
