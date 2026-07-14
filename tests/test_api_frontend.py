"""Tests for serving the built SPA from the API (when a build is present)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatweave.api.app import create_app
from threatweave.graph.memory import InMemoryGraphStore

# The real submodule, fetched via sys.modules: ``threatweave.api.__init__``
# re-exports the FastAPI ``app`` object, which shadows the submodule on plain
# attribute access (so ``import threatweave.api.app as m`` / monkeypatch string
# targets would resolve to the app object instead of the module).
_APP_MODULE = sys.modules["threatweave.api.app"]


def test_frontend_not_mounted_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no build directory, the API still works and '/' is not served."""
    monkeypatch.setattr(_APP_MODULE, "_FRONTEND_DIST", Path("does/not/exist"))
    client = TestClient(create_app(store=InMemoryGraphStore()))

    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 404


def test_frontend_served_when_built(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>ThreatWeave UI</html>", encoding="utf-8")
    monkeypatch.setattr(_APP_MODULE, "_FRONTEND_DIST", dist)

    client = TestClient(create_app(store=InMemoryGraphStore()))

    # SPA index is served at the root...
    root = client.get("/")
    assert root.status_code == 200
    assert "ThreatWeave UI" in root.text

    # ...but the API routes still take priority over the static mount.
    assert client.get("/health").json() == {"status": "ok"}
