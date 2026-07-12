"""The ``LLMProvider`` interface and its data contracts.

This module defines the *shape* of the AI enrichment layer without wiring in any
provider. Concrete implementations (API-based or self-hosted) arrive in later
phases; until then the methods raise :class:`NotImplementedError` so nothing
accidentally calls out to a model.

The interface is deliberately narrow — exactly the three operations where AI adds
value at ingestion time:

* :meth:`LLMProvider.extract`  — pull IOCs/TTPs out of unstructured prose.
* :meth:`LLMProvider.embed`    — produce vector embeddings for semantic search.
* :meth:`LLMProvider.narrate`  — write an on-demand explanatory summary.

Correlation is **not** here by design: relating indicators is graph logic, not a
model call.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import BaseModel, Field

from threatweave.models.ioc import IOC


class ExtractionResult(BaseModel):
    """Structured output of :meth:`LLMProvider.extract`.

    Holds the indicators recovered from free text plus any TTP references (e.g.
    MITRE ATT&CK technique ids). Extraction only *identifies* entities; it never
    asserts relationships between them.
    """

    iocs: list[IOC] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)


class LLMProvider(ABC):
    """Abstract, swappable interface to an AI backend.

    Concrete subclasses will be selected at runtime from configuration (see
    ``LLMSettings.provider``). All methods are currently unimplemented.
    """

    @abstractmethod
    def extract(self, text: str) -> ExtractionResult:
        """Extract IOCs and TTPs from unstructured ``text``.

        Reserved for the AI extraction phase. Complements the deterministic
        regex parser by recovering indicators that patterns cannot, such as TTPs
        described in prose.
        """
        raise NotImplementedError

    @abstractmethod
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return an embedding vector for each input string.

        Reserved for the embeddings phase (stored in pgvector) to enable
        semantic correlation beyond exact matching.
        """
        raise NotImplementedError

    @abstractmethod
    def narrate(self, subgraph: object) -> str:
        """Write a human-readable narrative explaining a correlation result.

        Reserved for the narratives phase. Takes a correlation ``Subgraph`` and
        produces an on-demand textual summary. Typed as ``object`` here to avoid
        a premature dependency direction; the concrete implementation will accept
        ``threatweave.models.graph.Subgraph``.
        """
        raise NotImplementedError
