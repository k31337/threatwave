"""Tests for the /api/narrative endpoint (LLM mocked)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import FakeProvider
from threatweave.api.app import create_app
from threatweave.connectors.document import DocumentIntel
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_document
from threatweave.llm.base import ExtractionResult
from threatweave.models.ioc import IOC, IOCType


def _store_with_ioc() -> InMemoryGraphStore:
    store = InMemoryGraphStore()
    ingest_document(
        store,
        DocumentIntel(
            report_name="Op X",
            source="s",
            text="t",
            iocs=[IOC(value="198.51.100.23", type=IOCType.IPV4)],
            extraction=ExtractionResult(),
        ),
    )
    return store


def test_narrative_returns_text_and_model() -> None:
    provider = FakeProvider(narrative="These indicators cluster around one campaign.")
    app = create_app(store=_store_with_ioc(), provider=provider)
    with TestClient(app) as client:
        response = client.get("/api/narrative", params={"ioc": "198.51.100.23"})

    assert response.status_code == 200
    body = response.json()
    assert body["ioc"] == "198.51.100.23"
    assert body["narrative"] == "These indicators cluster around one campaign."
    assert body["model"] == "fake-narrative-model"
    # The narrative was generated from the correlated subgraph.
    assert provider.narrated and provider.narrated[0].nodes


def test_narrative_unknown_ioc_returns_404() -> None:
    app = create_app(store=_store_with_ioc(), provider=FakeProvider())
    with TestClient(app) as client:
        response = client.get("/api/narrative", params={"ioc": "9.9.9.9"})
    assert response.status_code == 404


def test_narrative_without_provider_returns_503() -> None:
    # No provider injected and LLM_PROVIDER defaults to none -> disabled.
    app = create_app(store=_store_with_ioc())
    with TestClient(app) as client:
        response = client.get("/api/narrative", params={"ioc": "198.51.100.23"})
    assert response.status_code == 503
