"""Tests for the multi-source ingestion runner (mocked connectors, no network)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from threatweave.config import Settings
from threatweave.connectors.abusech import FeodoTrackerConnector, URLhausConnector
from threatweave.connectors.base import Connector
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest_runner import enabled_sources, run_ingest
from threatweave.ingest_state import IngestState
from threatweave.models.ioc import IOC


def _mock_connector(cls: type, payload: Any, **kwargs: Any) -> Connector:
    """Build a real connector wired to a MockTransport serving ``payload``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return cls(client=client, **kwargs)


def test_run_ingest_writes_from_multiple_feeds(
    tmp_path: Path, feodo_payload: list, urlhaus_payload: dict
) -> None:
    store = InMemoryGraphStore()
    state = IngestState(tmp_path / "state.json")
    connectors = {
        "feodo": _mock_connector(FeodoTrackerConnector, feodo_payload),
        "urlhaus": _mock_connector(URLhausConnector, urlhaus_payload),
    }

    outcomes = run_ingest(
        ["feodo", "urlhaus"],
        settings=Settings(),
        store=store,
        state=state,
        connectors=connectors,
    )

    # Both feeds wrote, and the shared IP is one node across sources.
    assert outcomes["feodo"].written == 2
    assert outcomes["urlhaus"].written == 4
    assert store.get_node("ioc:ipv4:203.0.113.20") is not None
    assert store.get_node("ioc:domain:malicious.example") is not None
    # Outcomes were persisted per source.
    assert state.get("feodo").status == "ok"
    assert state.get("urlhaus").total_iocs == 4


def test_run_ingest_skips_unchanged_feed(tmp_path: Path, feodo_payload: list) -> None:
    store = InMemoryGraphStore()
    state = IngestState(tmp_path / "state.json")
    settings = Settings()

    run_ingest(
        ["feodo"],
        settings=settings,
        store=store,
        state=state,
        connectors={"feodo": _mock_connector(FeodoTrackerConnector, feodo_payload)},
    )
    # Second run with an identical payload: dedup by hash short-circuits the write.
    outcomes = run_ingest(
        ["feodo"],
        settings=settings,
        store=store,
        state=state,
        connectors={"feodo": _mock_connector(FeodoTrackerConnector, feodo_payload)},
    )

    assert outcomes["feodo"].skipped is True
    assert outcomes["feodo"].written == 0
    assert state.get("feodo").new_iocs == 0


def test_run_ingest_isolates_source_failure(tmp_path: Path, feodo_payload: list) -> None:
    store = InMemoryGraphStore()
    state = IngestState(tmp_path / "state.json")

    class _Boom(Connector):
        name = "urlhaus"

        def fetch_iocs(self) -> list[IOC]:
            raise httpx.ConnectError("boom")

    outcomes = run_ingest(
        ["urlhaus", "feodo"],
        settings=Settings(),
        store=store,
        state=state,
        connectors={
            "urlhaus": _Boom(),
            "feodo": _mock_connector(FeodoTrackerConnector, feodo_payload),
        },
    )

    # The failing source is recorded as an error but does not stop the good one.
    assert "urlhaus" not in outcomes
    assert state.get("urlhaus").status == "error"
    assert outcomes["feodo"].written == 2


def test_enabled_sources_respects_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSECH_ENABLED", "true")
    monkeypatch.setenv("OTX_ENABLED", "false")
    settings = Settings()

    names = enabled_sources(settings)

    assert set(names) == {"urlhaus", "malwarebazaar", "feodo"}
    assert "otx" not in names
