"""Cost guardrails: structured-feed ingestion must never call the AI provider.

The project reserves AI (extraction + embeddings) for free-text ``ingest-doc``.
Structured feeds carry their indicators in fields, so their scheduled ingestion
must go by normalization + batched upsert alone — zero LLM calls, zero embeddings.
These tests fail loudly if that boundary ever regresses.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from threatweave.config import Settings
from threatweave.connectors.abusech import FeodoTrackerConnector, URLhausConnector
from threatweave.connectors.base import Connector
from threatweave.connectors.otx import OTXConnector
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest_runner import run_ingest
from threatweave.ingest_state import IngestState


def _mock_connector(cls: type, payload: Any, **kwargs: Any) -> Connector:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return cls(client=client, **kwargs)


def test_abusech_feed_ingest_makes_zero_ai_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    feodo_payload: list,
    urlhaus_payload: dict,
) -> None:
    # Any attempt to obtain or use an AI provider must blow up.
    def _forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("structured feed ingestion must not touch the LLM")

    monkeypatch.setattr("threatweave.llm.factory.get_provider", _forbidden)
    monkeypatch.setattr("threatweave.ingest._embed_and_cache", _forbidden)

    store = InMemoryGraphStore()
    state = IngestState(tmp_path / "state.json")
    outcomes = run_ingest(
        ["feodo", "urlhaus"],
        settings=Settings(),
        store=store,
        state=state,
        connectors={
            "feodo": _mock_connector(FeodoTrackerConnector, feodo_payload),
            "urlhaus": _mock_connector(URLhausConnector, urlhaus_payload),
        },
    )

    # Both feeds ingested cleanly (an AI call would have raised, and run_ingest
    # would have recorded that source as an error instead of "ok").
    assert outcomes["feodo"].written == 2
    assert outcomes["urlhaus"].written == 4
    assert state.get("feodo").status == "ok"
    assert state.get("urlhaus").status == "ok"
    assert store.get_node("ioc:ipv4:203.0.113.20") is not None


def test_otx_scheduled_ingest_skips_ai_when_flag_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, otx_payload: dict
) -> None:
    # With OTX_EMBED_DESCRIPTIONS off (the default), the OTX path must not even
    # build an AI provider.
    provider_calls: list[int] = []
    monkeypatch.setattr(
        "threatweave.llm.factory.get_provider",
        lambda _settings: provider_calls.append(1),
    )

    store = InMemoryGraphStore()
    state = IngestState(tmp_path / "state.json")
    outcomes = run_ingest(
        ["otx"],
        settings=Settings(),  # OTX_EMBED_DESCRIPTIONS defaults to False
        store=store,
        state=state,
        connectors={"otx": _mock_connector(OTXConnector, otx_payload, api_key="x")},
    )

    assert provider_calls == []  # provider never constructed
    assert outcomes["otx"].written == 6  # campaigns/IOCs still ingested
    assert state.get("otx").status == "ok"
    # A campaign hub exists, but no embeddings were computed (no vector store).
    assert store.get_node("campaign:Synthetic APT-Test Infrastructure") is not None
