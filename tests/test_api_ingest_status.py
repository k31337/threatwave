"""Tests for the GET /api/ingest/status observability endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatweave.api.app import create_app
from threatweave.config import get_settings
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest_state import IngestState


def _client(state_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("INGEST_STATE_PATH", str(state_path))
    get_settings.cache_clear()  # pick up the patched path
    return TestClient(create_app(store=InMemoryGraphStore()))


def test_status_reports_recorded_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "state.json"
    state = IngestState(state_path)
    state.record("feodo", status="ok", new_iocs=2, total_iocs=2, payload_hash="h1")
    state.record("urlhaus", status="error", error="connection refused")

    client = _client(state_path, monkeypatch)
    response = client.get("/api/ingest/status")

    assert response.status_code == 200
    sources = {s["source"]: s for s in response.json()["sources"]}
    assert sources["feodo"]["status"] == "ok"
    assert sources["feodo"]["new_iocs"] == 2
    assert sources["feodo"]["last_run"] is not None
    assert sources["urlhaus"]["status"] == "error"
    assert sources["urlhaus"]["error"] == "connection refused"


def test_status_is_empty_before_any_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path / "missing.json", monkeypatch)
    response = client.get("/api/ingest/status")

    assert response.status_code == 200
    assert response.json() == {"sources": []}
