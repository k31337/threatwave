"""Orchestration for scheduled, multi-source ingestion.

Ties the connectors, the batched graph writes and the persistent
:class:`~threatweave.ingest_state.IngestState` together behind one entry point,
:func:`run_ingest`, used by ``threatweave ingest``. Responsibilities:

* select which sources to run (all enabled, or an explicit subset),
* dedup by payload hash — skip a source whose feed is unchanged since last run,
* keep structured feeds AI-free (abuse.ch never calls the LLM; OTX embeds pulse
  descriptions only when ``OTX_EMBED_DESCRIPTIONS`` is on),
* record each source's outcome and isolate failures so one bad feed does not
  abort the others.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from threatweave.config import Settings
from threatweave.connectors.abusech import (
    FeodoTrackerConnector,
    MalwareBazaarConnector,
    URLhausConnector,
)
from threatweave.connectors.base import Connector
from threatweave.connectors.otx import OTXConnector
from threatweave.graph.base import GraphStore
from threatweave.ingest import ingest_feed, ingest_otx_payload
from threatweave.ingest_state import IngestState
from threatweave.models.ioc import IOC
from threatweave.vector.base import content_hash


@dataclass(frozen=True)
class IngestOutcome:
    """The result of ingesting one source in a single run."""

    seen: int  # indicators the feed currently reports
    written: int  # indicators written to the graph this run (0 when skipped)
    digest: str  # payload hash, stored to skip an unchanged next pull
    skipped: bool  # True when the feed was unchanged and left untouched


def _iocs_digest(iocs: list[IOC]) -> str:
    """Return a stable hash of a normalized IOC set (order-independent)."""
    joined = "\n".join(sorted(f"{ioc.type.value}:{ioc.value}" for ioc in iocs))
    return content_hash(joined)


def _feed_ingest(source_name: str) -> Callable[..., IngestOutcome]:
    """Build the ingest strategy for a plain structured feed (no AI, ever)."""

    def _ingest(
        connector: Connector, store: GraphStore, settings: Settings, last_digest: str | None
    ) -> IngestOutcome:
        iocs = connector.fetch_iocs()
        digest = _iocs_digest(iocs)
        if digest == last_digest:
            return IngestOutcome(seen=len(iocs), written=0, digest=digest, skipped=True)
        written = ingest_feed(store, iocs, source=source_name)
        return IngestOutcome(seen=len(iocs), written=written, digest=digest, skipped=False)

    return _ingest


def _otx_ingest(
    connector: Connector, store: GraphStore, settings: Settings, last_digest: str | None
) -> IngestOutcome:
    """Ingest OTX with campaign structure; embed descriptions only if opted in."""
    assert isinstance(connector, OTXConnector)
    payload = connector.fetch_payload()
    digest = content_hash(json.dumps(payload, sort_keys=True, default=str))
    seen = sum(len(p.get("indicators", [])) for p in payload.get("results", []))
    if digest == last_digest:
        return IngestOutcome(seen=seen, written=0, digest=digest, skipped=True)

    provider = None
    vector_store = None
    if settings.otx.embed_descriptions:
        # Opt-in AI path: build the provider/vector store lazily, use, then close.
        from threatweave.llm.factory import get_provider
        from threatweave.vector.factory import build_vector_store

        provider = get_provider(settings)
        vector_store = build_vector_store(settings)
    try:
        written = ingest_otx_payload(
            store, payload, provider=provider, vector_store=vector_store
        )
    finally:
        if vector_store is not None:
            vector_store.close()
    return IngestOutcome(seen=seen, written=written, digest=digest, skipped=False)


@dataclass(frozen=True)
class Source:
    """A registered ingestion source: how to build it, run it and gate it."""

    name: str
    make_connector: Callable[[Settings], Connector]
    ingest: Callable[..., IngestOutcome]
    is_enabled: Callable[[Settings], bool]


def build_sources() -> dict[str, Source]:
    """Return the registry of all known ingestion sources, keyed by name."""
    return {
        "otx": Source(
            name="otx",
            make_connector=lambda s: OTXConnector(s.otx.api_key, s.otx.base_url),
            ingest=_otx_ingest,
            is_enabled=lambda s: s.otx.enabled,
        ),
        "urlhaus": Source(
            name="urlhaus",
            make_connector=lambda s: URLhausConnector(
                s.abusech.urlhaus_base_url, auth_key=s.abusech.auth_key
            ),
            ingest=_feed_ingest("urlhaus"),
            is_enabled=lambda s: s.abusech.enabled,
        ),
        "malwarebazaar": Source(
            name="malwarebazaar",
            make_connector=lambda s: MalwareBazaarConnector(
                s.abusech.malwarebazaar_base_url, auth_key=s.abusech.auth_key
            ),
            ingest=_feed_ingest("malwarebazaar"),
            is_enabled=lambda s: s.abusech.enabled,
        ),
        "feodo": Source(
            name="feodo",
            make_connector=lambda s: FeodoTrackerConnector(s.abusech.feodo_base_url),
            ingest=_feed_ingest("feodo"),
            is_enabled=lambda s: s.abusech.enabled,
        ),
    }


def known_sources() -> list[str]:
    """Return the names of every registered source."""
    return list(build_sources())


def enabled_sources(settings: Settings) -> list[str]:
    """Return the names of sources enabled in ``settings`` (for ``--all``)."""
    return [name for name, src in build_sources().items() if src.is_enabled(settings)]


def run_ingest(
    names: list[str],
    *,
    settings: Settings,
    store: GraphStore,
    state: IngestState,
    connectors: Mapping[str, Connector] | None = None,
) -> dict[str, IngestOutcome]:
    """Ingest each named source, recording outcomes and isolating failures.

    ``connectors`` lets a caller inject pre-built connectors (used in tests to
    supply mock-transport clients); otherwise each source builds its own from
    ``settings`` and closes it afterwards. A source that raises is logged and
    recorded as an error, and the run continues with the rest.
    """
    sources = build_sources()
    outcomes: dict[str, IngestOutcome] = {}
    for name in names:
        source = sources[name]
        log = logging.getLogger(f"threatweave.ingest.{name}")
        injected = connectors is not None and name in connectors
        connector = connectors[name] if injected else source.make_connector(settings)
        try:
            outcome = source.ingest(connector, store, settings, state.payload_hash(name))
            if outcome.skipped:
                log.info("feed unchanged (%d indicators); skipped", outcome.seen)
            else:
                log.info(
                    "ingested %d IOC nodes (%d indicators seen)",
                    outcome.written,
                    outcome.seen,
                )
            state.record(
                name,
                status="ok",
                new_iocs=outcome.written,
                total_iocs=outcome.seen,
                payload_hash=outcome.digest,
            )
            outcomes[name] = outcome
        except Exception as exc:  # noqa: BLE001 - isolate per-source failures
            log.error("ingestion failed: %s", exc)
            state.record(name, status="error", error=str(exc))
        finally:
            if not injected:
                connector.close()
    return outcomes
