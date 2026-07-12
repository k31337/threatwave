"""Tests for the FastAPI correlation endpoint, using an injected in-memory store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatweave.api.app import create_app
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_otx_payload

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "otx_subscribed.json"


@pytest.fixture
def client() -> TestClient:
    payload: dict[str, Any] = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    store = InMemoryGraphStore()
    ingest_otx_payload(store, payload)
    app = create_app(store=store)
    return TestClient(app)


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_correlate_returns_subgraph(client: TestClient) -> None:
    response = client.get("/api/correlate", params={"ioc": "203.0.113.10", "depth": 2})
    assert response.status_code == 200

    body = response.json()
    labels = {node["label"] for node in body["nodes"]}
    assert "203.0.113.10" in labels
    assert "malicious.example" in labels
    assert body["edges"], "expected at least one relationship edge"


def test_correlate_unknown_returns_404(client: TestClient) -> None:
    response = client.get("/api/correlate", params={"ioc": "9.9.9.9"})
    assert response.status_code == 404


def test_correlate_rejects_out_of_range_depth(client: TestClient) -> None:
    response = client.get("/api/correlate", params={"ioc": "203.0.113.10", "depth": 9})
    assert response.status_code == 422  # validation error from Query(le=4)
