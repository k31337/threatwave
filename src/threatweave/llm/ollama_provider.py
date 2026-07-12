"""Placeholder for a self-hosted Ollama implementation of :class:`LLMProvider`.

Wired into the factory so the provider is swappable via configuration, but not
implemented yet. It exists to keep the OpenAI/self-hosted boundary explicit; the
methods raise until the self-hosting phase.
"""

from __future__ import annotations

from collections.abc import Sequence

from threatweave.llm.base import ExtractionResult, LLMProvider


class OllamaProvider(LLMProvider):
    """Not implemented yet — reserved for local, self-hosted inference."""

    def __init__(self, *, model: str = "", base_url: str = "http://localhost:11434") -> None:
        self._model = model
        self._base_url = base_url

    def extract(self, text: str) -> ExtractionResult:
        raise NotImplementedError("Ollama provider is not implemented yet")

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise NotImplementedError("Ollama provider is not implemented yet")

    def narrate(self, subgraph: object) -> str:
        raise NotImplementedError("Ollama provider is not implemented yet")
