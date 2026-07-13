"""Tests for narrative generation: formatting, safeguards and the provider."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from threatweave.llm.narrative import (
    DISCLAIMER,
    build_messages,
    finalize_narrative,
    format_evidence,
)
from threatweave.llm.openai_provider import OpenAIProvider
from threatweave.models.graph import Edge, Node, RelationType, Subgraph


def _subgraph() -> Subgraph:
    return Subgraph(
        nodes=[
            Node(id="campaign:Op X", kind="campaign", label="Op X"),
            Node(id="ioc:ipv4:1.1.1.1", kind="ioc", label="1.1.1.1"),
            Node(id="campaign:Op Y", kind="campaign", label="Op Y"),
        ],
        edges=[
            Edge(source="ioc:ipv4:1.1.1.1", target="campaign:Op X", type=RelationType.PART_OF),
            Edge(
                source="campaign:Op X",
                target="campaign:Op Y",
                type=RelationType.SEMANTIC_SIMILARITY,
                score=0.94,
            ),
        ],
    )


def test_format_evidence_lists_nodes_and_edges() -> None:
    evidence = format_evidence(_subgraph())
    assert "1.1.1.1" in evidence
    assert "part_of" in evidence
    # Semantic edges carry their score.
    assert "semantic_similarity (score=0.940)" in evidence


def test_format_evidence_handles_no_edges() -> None:
    evidence = format_evidence(Subgraph(nodes=[Node(id="x", kind="ioc", label="x")]))
    assert "(none)" in evidence


def test_finalize_appends_disclaimer() -> None:
    assert finalize_narrative("Some narrative.").endswith(DISCLAIMER)


def test_finalize_empty_text_returns_disclaimer_only() -> None:
    assert finalize_narrative("   ") == DISCLAIMER


def _make_client(content: str | None) -> tuple[Any, dict[str, Any]]:
    """Fake client mimicking client.chat.completions.create(...)."""
    calls: dict[str, Any] = {}
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=SimpleNamespace(prompt_tokens=200, completion_tokens=60),
    )

    class _Completions:
        def create(self, **kwargs: Any) -> Any:
            calls.update(kwargs)
            return completion

    client = SimpleNamespace(chat=SimpleNamespace(completions=_Completions()))
    return client, calls


def test_narrate_uses_narrative_model_and_only_subgraph_evidence() -> None:
    client, calls = _make_client("Op X and Op Y share IP 1.1.1.1.")
    provider = OpenAIProvider(client=client, narrative_model="gpt-5.4-mini")

    narrative = provider.narrate(_subgraph())

    assert calls["model"] == "gpt-5.4-mini"
    # The model is fed the deterministic evidence and nothing else in the user turn.
    assert calls["messages"] == build_messages(_subgraph())
    # Disclaimer is appended by code, independent of the model output.
    assert narrative.endswith(DISCLAIMER)
    assert "Op X and Op Y share IP 1.1.1.1." in narrative


def test_narrate_handles_empty_model_output() -> None:
    client, _ = _make_client(None)
    provider = OpenAIProvider(client=client)
    assert provider.narrate(_subgraph()) == DISCLAIMER


def test_narrative_model_property_exposed() -> None:
    client, _ = _make_client("x")
    provider = OpenAIProvider(client=client, narrative_model="gpt-5.5")
    assert provider.narrative_model == "gpt-5.5"
