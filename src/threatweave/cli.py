"""Command-line interface for ThreatWeave.

Exposes ``ingest`` (scheduled multi-source feed ingestion), ``ingest-doc``
(hybrid extraction of a threat report into the graph) and ``demo`` (launch the
API against the in-memory sample graph, no keys required).

    threatweave ingest --all
    threatweave ingest --source urlhaus --source feodo
    threatweave ingest-doc --url https://example.com/report
    threatweave ingest-doc --file report.txt
    threatweave ingest-doc --text "APT-Sample phishing campaign ..."
    threatweave demo
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from threatweave.config import get_settings
from threatweave.connectors.base import Connector
from threatweave.connectors.document import DocumentConnector
from threatweave.graph.base import GraphStore
from threatweave.graph.factory import build_store
from threatweave.ingest import ingest_document
from threatweave.ingest_runner import enabled_sources, known_sources, run_ingest
from threatweave.ingest_state import IngestState
from threatweave.llm.base import LLMProvider
from threatweave.llm.factory import get_provider
from threatweave.vector.base import VectorStore
from threatweave.vector.factory import build_vector_store

logger = logging.getLogger(__name__)


def run_ingest_doc(
    args: argparse.Namespace,
    *,
    store: GraphStore | None = None,
    provider: LLMProvider | None = None,
    vector_store: VectorStore | None = None,
) -> None:
    """Execute the ``ingest-doc`` command.

    ``store``, ``provider`` and ``vector_store`` may be injected (used in tests);
    otherwise they are built from configuration. When a vector store is
    configured (``VECTOR_BACKEND``), the document is also embedded for semantic
    similarity.
    """
    settings = get_settings()
    provider = provider or get_provider(settings)
    owns_store = store is None
    store = store or build_store(settings)
    owns_vector_store = vector_store is None
    vector_store = vector_store or build_vector_store(settings)

    connector = DocumentConnector(provider, max_input_chars=settings.llm.max_input_chars)
    try:
        if args.url:
            intel = connector.from_url(args.url)
        elif args.file:
            path = Path(args.file)
            intel = connector.from_text(
                path.read_text(encoding="utf-8"), name=path.name, source=str(path)
            )
        else:
            intel = connector.from_text(args.text, source="inline-text")

        campaign = ingest_document(
            store, intel, provider=provider, vector_store=vector_store
        )
    finally:
        connector.close()
        if owns_store:
            store.close()
        if owns_vector_store and vector_store is not None:
            vector_store.close()

    extraction = intel.extraction
    print(
        f"Ingested '{intel.report_name}' (source: {intel.source})\n"
        f"  campaign: {campaign.id}\n"
        f"  IOCs:     {len(intel.iocs)}\n"
        f"  TTPs:     {len(extraction.ttps)} "
        f"({', '.join(t.technique_id for t in extraction.ttps) or '-'})\n"
        f"  actor:    {extraction.actor or '-'}\n"
        f"  sectors:  {', '.join(extraction.target_sectors) or '-'}"
    )


def run_ingest_cmd(
    args: argparse.Namespace,
    *,
    store: GraphStore | None = None,
    state: IngestState | None = None,
    connectors: dict[str, Connector] | None = None,
) -> None:
    """Execute the ``ingest`` command: run enabled (or named) feed sources once.

    Cron-friendly: it ingests and exits, so any scheduler (cron, Windows Task
    Scheduler, a VPS timer) can drive the cadence. ``store``, ``state`` and
    ``connectors`` may be injected in tests. Structured feeds go through the
    AI-free batch path.
    """
    settings = get_settings()

    if args.all:
        names = enabled_sources(settings)
        if not names:
            print(
                "No sources enabled. Set OTX_ENABLED / ABUSECH_ENABLED, or pass "
                "--source <name>."
            )
            return
    else:
        names = args.source
        unknown = [n for n in names if n not in known_sources()]
        if unknown:
            raise SystemExit(
                f"unknown source(s): {', '.join(unknown)}. "
                f"Known: {', '.join(known_sources())}"
            )

    owns_store = store is None
    store = store or build_store(settings)
    state = state or IngestState(settings.ingest_state_path)

    try:
        outcomes = run_ingest(
            names, settings=settings, store=store, state=state, connectors=connectors
        )
    finally:
        if owns_store:
            store.close()

    for name in names:
        outcome = outcomes.get(name)
        if outcome is None:
            print(f"  {name}: ERROR (see logs)")
        elif outcome.skipped:
            print(f"  {name}: unchanged ({outcome.seen} indicators); skipped")
        else:
            print(f"  {name}: {outcome.written} IOCs written ({outcome.seen} seen)")


def run_demo(args: argparse.Namespace) -> None:
    """Execute the ``demo`` command: serve the API on the seeded in-memory graph.

    Forces ``GRAPH_BACKEND=memory`` and ``SEED_SAMPLE=true`` so the API starts
    from the synthetic sample with no database and no API keys — the one-command
    way to try the frontend end to end. Child processes spawned by ``--reload``
    inherit these environment variables.
    """
    os.environ["GRAPH_BACKEND"] = "memory"
    os.environ["SEED_SAMPLE"] = "true"
    get_settings.cache_clear()  # drop any Settings cached before we set the env

    import uvicorn

    logger.info(
        "starting ThreatWeave demo on http://%s:%d "
        "(in-memory graph seeded from data/samples; try ioc=malicious.example)",
        args.host,
        args.port,
    )
    uvicorn.run(
        "threatweave.api.app:app", host=args.host, port=args.port, reload=args.reload
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(prog="threatweave")
    subcommands = parser.add_subparsers(dest="command", required=True)

    ingest = subcommands.add_parser(
        "ingest",
        help="Run scheduled feed ingestion for all enabled sources, or a subset.",
    )
    selection = ingest.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--all", action="store_true", help="Ingest every enabled source."
    )
    selection.add_argument(
        "--source",
        action="append",
        metavar="NAME",
        help=f"Ingest a specific source (repeatable). Known: {', '.join(known_sources())}.",
    )
    ingest.set_defaults(func=run_ingest_cmd)

    ingest_doc = subcommands.add_parser(
        "ingest-doc", help="Ingest a threat report (URL, file or text) into the graph."
    )
    source = ingest_doc.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="URL of the report to fetch and ingest.")
    source.add_argument("--file", help="Path to a local report file.")
    source.add_argument("--text", help="Inline report text.")
    ingest_doc.set_defaults(func=run_ingest_doc)

    demo = subcommands.add_parser(
        "demo",
        help="Serve the API on the seeded in-memory sample graph (no keys needed).",
    )
    demo.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    demo.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")
    demo.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development."
    )
    demo.set_defaults(func=run_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
