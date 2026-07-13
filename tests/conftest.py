"""Shared pytest fixtures."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from threatweave.graph.memory import InMemoryGraphStore
from threatweave.llm.base import TTP, ExtractionResult, LLMProvider
from threatweave.models.graph import Subgraph

_SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


class FakeProvider(LLMProvider):
    """A stub LLM provider with fixed extraction and deterministic embeddings.

    Lets the whole ingestion pipeline be tested offline without any API calls.
    ``embeddings`` maps exact input text to a fixed vector; unmapped text gets a
    stable hash-derived vector. Call counters make caching observable.
    """

    narrative_model = "fake-narrative-model"

    def __init__(
        self,
        result: ExtractionResult | None = None,
        *,
        embeddings: dict[str, list[float]] | None = None,
        narrative: str = "Fixed narrative.",
    ) -> None:
        self.result = result or ExtractionResult()
        self.calls: list[str] = []
        self.embed_calls = 0
        self._embeddings = embeddings or {}
        self._narrative = narrative
        self.narrated: list[Subgraph] = []

    def extract(self, text: str) -> ExtractionResult:
        self.calls.append(text)
        return self.result

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.embed_calls += 1
        return [self._embeddings.get(text, self._hash_vector(text)) for text in texts]

    @staticmethod
    def _hash_vector(text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return [byte / 255 for byte in digest[:8]]

    def narrate(self, subgraph: Subgraph) -> str:
        self.narrated.append(subgraph)
        return self._narrative


@pytest.fixture
def otx_payload() -> dict[str, Any]:
    """The synthetic OTX subscribed-pulses response used for offline tests."""
    return json.loads((_SAMPLES / "otx_subscribed.json").read_text(encoding="utf-8"))


@pytest.fixture
def sample_report() -> str:
    """The synthetic free-text threat report used for offline tests."""
    return (_SAMPLES / "threat_report.txt").read_text(encoding="utf-8")


@pytest.fixture
def store() -> InMemoryGraphStore:
    """A fresh in-memory graph store."""
    return InMemoryGraphStore()


@pytest.fixture
def fake_provider() -> FakeProvider:
    """A FakeProvider returning a representative extraction result."""
    return FakeProvider(
        ExtractionResult(
            ttps=[
                TTP(technique_id="T1566.001", name="Spearphishing Attachment"),
                TTP(technique_id="T1071.001", name="Web Protocols"),
            ],
            actor="APT-Sample",
            target_sectors=["Finance", "financial services"],
        )
    )
