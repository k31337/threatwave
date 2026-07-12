"""Pluggable AI enrichment layer.

All AI access goes through the :class:`LLMProvider` interface so the concrete
backend (OpenAI via API, or self-hosted Ollama) is interchangeable.

Architecture rule: AI is reserved for ingestion-time enrichment only —
extraction, embeddings and narratives. It is **never** used to correlate IOCs or
decide structural relationships; that is deterministic graph logic.
"""

from threatweave.llm.base import TTP, ExtractionResult, LLMProvider

__all__ = ["LLMProvider", "ExtractionResult", "TTP"]
