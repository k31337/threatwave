"""Provider selection from configuration."""

from __future__ import annotations

from threatweave.config import Settings
from threatweave.llm.base import LLMProvider


def get_provider(settings: Settings) -> LLMProvider:
    """Return the configured :class:`LLMProvider`.

    Raises ``ValueError`` when no usable provider is configured (the default
    ``LLM_PROVIDER=none``), so callers that need AI fail with a clear message
    instead of silently doing nothing.
    """
    provider = settings.llm.provider.lower()

    if provider == "openai":
        # Imported lazily so non-AI code paths don't require the openai package.
        from threatweave.llm.openai_provider import OpenAIProvider

        return OpenAIProvider(
            api_key=settings.llm.api_key,
            model=settings.llm.model or "gpt-4o-mini",
            max_output_tokens=settings.llm.max_output_tokens,
            max_retries=settings.llm.max_retries,
        )

    if provider == "ollama":
        from threatweave.llm.ollama_provider import OllamaProvider

        return OllamaProvider(model=settings.llm.model)

    raise ValueError(
        f"no usable LLM provider configured (LLM_PROVIDER={settings.llm.provider!r}); "
        "set LLM_PROVIDER=openai and provide LLM_API_KEY"
    )
