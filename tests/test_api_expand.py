"""Tests for the deterministic ``/api/expand`` node-neighbourhood endpoint."""

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
    return TestClient(create_app(store=store))


def test_expand_ioc_node_returns_neighbourhood(client: TestClient) -> None:
    response = client.get(
        "/api/expand", params={"id": "ioc:ipv4:203.0.113.10", "depth": 2}
    )
    assert response.status_code == 200

    body = response.json()
    ids = {node["id"] for node in body["nodes"]}
    assert "ioc:ipv4:203.0.113.10" in ids
    assert body["edges"], "expected at least one relationship edge"


def test_expand_campaign_node(client: TestClient) -> None:
    # Discover a real campaign node id via correlate, then expand it.
    correlated = client.get(
        "/api/correlate", params={"ioc": "203.0.113.10", "depth": 2}
    ).json()
    campaign_ids = [n["id"] for n in correlated["nodes"] if n["kind"] == "campaign"]
    assert campaign_ids, "sample should contain a campaign node"

    response = client.get("/api/expand", params={"id": campaign_ids[0], "depth": 1})
    assert response.status_code == 200
    ids = {node["id"] for node in response.json()["nodes"]}
    assert campaign_ids[0] in ids


def test_expand_unknown_node_returns_404(client: TestClient) -> None:
    response = client.get("/api/expand", params={"id": "campaign:does-not-exist"})
    assert response.status_code == 404


def test_expand_rejects_out_of_range_depth(client: TestClient) -> None:
    response = client.get(
        "/api/expand", params={"id": "ioc:ipv4:203.0.113.10", "depth": 9}
    )
    assert response.status_code == 422
