"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from threatweave.graph.memory import InMemoryGraphStore

_SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


@pytest.fixture
def otx_payload() -> dict[str, Any]:
    """The synthetic OTX subscribed-pulses response used for offline tests."""
    return json.loads((_SAMPLES / "otx_subscribed.json").read_text(encoding="utf-8"))


@pytest.fixture
def store() -> InMemoryGraphStore:
    """A fresh in-memory graph store."""
    return InMemoryGraphStore()
