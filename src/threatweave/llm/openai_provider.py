"""OpenAI-backed implementation of :class:`LLMProvider`.

Only :meth:`extract` is implemented in this phase. It uses OpenAI Structured
Outputs so the model must return JSON matching a strict schema, which is then
validated and normalized into the internal :class:`ExtractionResult`.

Per the architecture rule, extraction covers **only** TTPs, actor and target
sectors — never IOCs (regex handles those) and never relationships (graph logic).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from openai import OpenAI
from pydantic import BaseModel

from threatweave.llm.base import TTP, ExtractionResult, LLMProvider
from threatweave.llm.cost import Usage, log_usage
from threatweave.llm.narrative import build_messages, finalize_narrative
from threatweave.models.graph import Subgraph
from threatweave.models.normalize import normalize_technique_id

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a cyber threat intelligence extraction engine. Read the report and "
    "extract ONLY:\n"
    "1. TTPs as MITRE ATT&CK technique ids (e.g. T1566 or sub-technique "
    "T1566.001), with the technique name and tactic when stated.\n"
    "2. The attributed threat actor / group, if named.\n"
    "3. The targeted sectors or industries.\n\n"
    "Do NOT output indicators of compromise (IP addresses, domains, URLs, file "
    "hashes) — those are handled separately. Do NOT invent data: if a field is "
    "not present in the text, leave it empty or null. Do NOT infer relationships."
)


class _LLMTTP(BaseModel):
    """LLM-facing TTP schema (kept minimal for strict structured outputs)."""

    technique_id: str
    name: str | None
    tactic: str | None


class _LLMExtraction(BaseModel):
    """LLM-facing extraction schema: no IOCs, all fields required by strict mode."""

    ttps: list[_LLMTTP]
    actor: str | None
    target_sectors: list[str]


class OpenAIProvider(LLMProvider):
    """Extraction provider backed by the OpenAI API."""

    def __init__(
        self,
        *,
        api_key: str = "",
        model: str = "gpt-4o-mini",
        client: OpenAI | None = None,
        max_output_tokens: int = 1_024,
        max_retries: int = 2,
        embed_model: str = "text-embedding-3-small",
        narrative_model: str = "gpt-5.4-mini",
    ) -> None:
        """Create the provider.

        Args:
            api_key: OpenAI API key (ignored if ``client`` is supplied).
            model: Chat model used for extraction.
            client: Optional pre-built OpenAI client (injected in tests).
            max_output_tokens: Cap on completion tokens per call.
            max_retries: Transient-error retries handled by the SDK client.
            embed_model: Model used by :meth:`embed`.
            narrative_model: Higher-quality model used by :meth:`narrate`.
        """
        self._model = model
        self._embed_model = embed_model
        self._narrative_model = narrative_model
        self._max_output_tokens = max_output_tokens
        self._client = client or OpenAI(api_key=api_key, max_retries=max_retries)

    def extract(self, text: str) -> ExtractionResult:
        """Extract TTPs, actor and target sectors from ``text``."""
        completion = self._client.beta.chat.completions.parse(
            model=self._model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            response_format=_LLMExtraction,
            max_tokens=self._max_output_tokens,
            temperature=0,
        )

        usage = getattr(completion, "usage", None)
        if usage is not None:
            log_usage(
                self._model,
                Usage(usage.prompt_tokens, usage.completion_tokens),
            )

        parsed = completion.choices[0].message.parsed
        if parsed is None:
            raise ValueError("OpenAI returned no parseable extraction result")
        return self._to_result(parsed)

    @staticmethod
    def _to_result(parsed: _LLMExtraction) -> ExtractionResult:
        """Validate and normalize raw model output into an ExtractionResult."""
        ttps: list[TTP] = []
        seen: set[str] = set()
        for raw in parsed.ttps:
            technique_id = normalize_technique_id(raw.technique_id)
            if not technique_id or technique_id in seen:
                # Drop malformed ids and duplicates so junk never reaches the graph.
                continue
            seen.add(technique_id)
            ttps.append(TTP(technique_id=technique_id, name=raw.name, tactic=raw.tactic))

        actor = parsed.actor.strip() if parsed.actor and parsed.actor.strip() else None
        sectors = [s.strip() for s in parsed.target_sectors if s and s.strip()]
        return ExtractionResult(ttps=ttps, actor=actor, target_sectors=sectors)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector per input string.

        Order is preserved so callers can zip inputs with their vectors. An empty
        input list short-circuits without calling the API.
        """
        inputs = list(texts)
        if not inputs:
            return []

        response = self._client.embeddings.create(model=self._embed_model, input=inputs)

        usage = getattr(response, "usage", None)
        if usage is not None:
            log_usage(
                self._embed_model,
                Usage(usage.prompt_tokens, 0),
            )

        # The API returns items with an ``index``; sort defensively to preserve order.
        ordered = sorted(response.data, key=lambda item: item.index)
        return [list(item.embedding) for item in ordered]

    def narrate(self, subgraph: Subgraph) -> str:
        """Write a narrative explaining a correlated subgraph.

        Uses the higher-quality narrative model. The model sees only the
        subgraph evidence, and a verification disclaimer is appended by code.
        """
        completion = self._client.chat.completions.create(
            model=self._narrative_model,
            messages=build_messages(subgraph),
            max_tokens=self._max_output_tokens,
            temperature=0.2,
        )

        usage = getattr(completion, "usage", None)
        if usage is not None:
            log_usage(
                self._narrative_model,
                Usage(usage.prompt_tokens, usage.completion_tokens),
            )

        text = completion.choices[0].message.content or ""
        return finalize_narrative(text)
