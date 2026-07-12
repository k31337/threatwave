"""Command-line interface for ThreatWeave.

Currently exposes ``ingest-doc``, which ingests a threat report (from a URL, a
file or inline text) into the graph using hybrid extraction.

    threatweave ingest-doc --url https://example.com/report
    threatweave ingest-doc --file report.txt
    threatweave ingest-doc --text "APT-Sample phishing campaign ..."
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from threatweave.config import get_settings
from threatweave.connectors.document import DocumentConnector
from threatweave.graph.base import GraphStore
from threatweave.graph.factory import build_store
from threatweave.ingest import ingest_document
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


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(prog="threatweave")
    subcommands = parser.add_subparsers(dest="command", required=True)

    ingest_doc = subcommands.add_parser(
        "ingest-doc", help="Ingest a threat report (URL, file or text) into the graph."
    )
    source = ingest_doc.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="URL of the report to fetch and ingest.")
    source.add_argument("--file", help="Path to a local report file.")
    source.add_argument("--text", help="Inline report text.")
    ingest_doc.set_defaults(func=run_ingest_doc)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
