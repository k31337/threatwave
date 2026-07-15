"""Tests for OpenAIProvider using a fully mocked OpenAI client (no network)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from threatweave.llm.cost import Usage, estimate_cost
from threatweave.llm.openai_provider import _LLMTTP, OpenAIProvider, _LLMExtraction
from threatweave.models.graph import Subgraph


def _make_client(parsed: _LLMExtraction | None) -> tuple[Any, dict[str, Any]]:
    """Build a fake client mimicking client.beta.chat.completions.parse(...)."""
    calls: dict[str, Any] = {}
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(parsed=parsed))],
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=40),
    )

    class _Completions:
        def parse(self, **kwargs: Any) -> Any:
            calls.update(kwargs)
            return completion

    client = SimpleNamespace(
        beta=SimpleNamespace(chat=SimpleNamespace(completions=_Completions()))
    )
    return client, calls


def _dual_client() -> tuple[Any, dict[str, dict[str, Any]]]:
    """Fake client capturing kwargs for both extract's parse() and narrate's create()."""
    calls: dict[str, dict[str, Any]] = {"parse": {}, "create": {}}
    parsed = _LLMExtraction(ttps=[], actor=None, target_sectors=[])
    parse_completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(parsed=parsed))],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
    )
    create_completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="A narrative."))],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
    )

    class _ParseCompletions:
        def parse(self, **kwargs: Any) -> Any:
            calls["parse"].update(kwargs)
            return parse_completion

    class _CreateCompletions:
        def create(self, **kwargs: Any) -> Any:
            calls["create"].update(kwargs)
            return create_completion

    client = SimpleNamespace(
        beta=SimpleNamespace(chat=SimpleNamespace(completions=_ParseCompletions())),
        chat=SimpleNamespace(completions=_CreateCompletions()),
    )
    return client, calls


def test_extract_normalizes_and_maps_ttps() -> None:
    parsed = _LLMExtraction(
        ttps=[
            _LLMTTP(technique_id="t1566.001", name="Spearphishing", tactic="Initial Access"),
            _LLMTTP(technique_id="not-a-technique", name=None, tactic=None),
            _LLMTTP(technique_id="T1566.001", name="dup", tactic=None),
        ],
        actor="  APT-Sample  ",
        target_sectors=["Finance", "  "],
    )
    client, calls = _make_client(parsed)
    provider = OpenAIProvider(client=client, model="gpt-4o-mini")

    result = provider.extract("some report text")

    # Junk id dropped, duplicate collapsed, valid id upper-cased.
    assert [t.technique_id for t in result.ttps] == ["T1566.001"]
    assert result.actor == "APT-Sample"
    assert result.target_sectors == ["Finance"]  # blank filtered


def test_extract_uses_structured_output_schema() -> None:
    parsed = _LLMExtraction(ttps=[], actor=None, target_sectors=[])
    client, calls = _make_client(parsed)
    provider = OpenAIProvider(client=client, model="gpt-4o-mini", max_output_tokens=256)

    provider.extract("text")

    assert calls["model"] == "gpt-4o-mini"
    assert calls["response_format"] is _LLMExtraction
    assert calls["max_completion_tokens"] == 256


def test_extract_raises_when_no_parsed_result() -> None:
    client, _ = _make_client(None)
    provider = OpenAIProvider(client=client)
    with pytest.raises(ValueError):
        provider.extract("text")


def test_embed_empty_input_short_circuits() -> None:
    client, _ = _make_client(_LLMExtraction(ttps=[], actor=None, target_sectors=[]))
    provider = OpenAIProvider(client=client)
    # No API attribute is touched because the empty list short-circuits.
    assert provider.embed([]) == []


def test_cost_estimation_known_and_unknown() -> None:
    # 1M input tokens at $0.15/Mtok == $0.15; unknown model -> None (tolerant).
    assert estimate_cost("gpt-4o-mini", Usage(1_000_000, 0)) == pytest.approx(0.15)
    assert estimate_cost("made-up-model", Usage(1000, 1000)) is None


def test_cost_estimation_narrative_model() -> None:
    # gpt-5.4-mini: $0.75/Mtok input + $4.50/Mtok output. 1M in + 1M out.
    cost = estimate_cost("gpt-5.4-mini", Usage(1_000_000, 1_000_000))
    assert cost == pytest.approx(0.75 + 4.50)
    # It is priced, not "unknown".
    assert cost is not None


def test_extract_sends_max_completion_tokens_not_max_tokens() -> None:
    # Regression: GPT-5 models reject `max_tokens` and require
    # `max_completion_tokens`; sending the former 400s. Reintroducing it here
    # (or dropping the new name) makes one of these assertions fail.
    client, calls = _dual_client()
    provider = OpenAIProvider(client=client, model="gpt-5-mini", max_output_tokens=256)

    provider.extract("some report text")

    assert calls["parse"]["max_completion_tokens"] == 256
    assert "max_tokens" not in calls["parse"]


def test_narrate_sends_max_completion_tokens_not_max_tokens() -> None:
    # Same regression guard for the narrative path (chat.completions.create).
    client, calls = _dual_client()
    provider = OpenAIProvider(
        client=client, narrative_model="gpt-5.4-mini", max_output_tokens=256
    )

    provider.narrate(Subgraph())

    assert calls["create"]["max_completion_tokens"] == 256
    assert "max_tokens" not in calls["create"]
