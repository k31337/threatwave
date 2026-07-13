"""The ``LLMProvider`` interface and its data contracts.

This module defines the *shape* of the AI enrichment layer. The interface is
deliberately narrow — exactly the three operations where AI adds value at
ingestion time:

* :meth:`LLMProvider.extract`  — pull TTPs, actor and target context out of prose.
* :meth:`LLMProvider.embed`    — produce vector embeddings for semantic search.
* :meth:`LLMProvider.narrate`  — write an on-demand explanatory summary.

Correlation is **not** here by design: relating indicators is graph logic, not a
model call. Obvious IOCs are **not** extracted here either — the deterministic
regex parser handles them, and the hybrid ingestion pipeline merges both. Keeping
IOCs out of the LLM schema avoids spending tokens on what regex already resolves.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from threatweave.models.graph import Subgraph


class TTP(BaseModel):
    """A tactic, technique or procedure mapped to MITRE ATT&CK.

    ``technique_id`` is the canonical ATT&CK id (e.g. ``T1566`` or a
    sub-technique ``T1566.001``); ``name`` and ``tactic`` are optional context.
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str | None = None
    tactic: str | None = None


class ExtractionResult(BaseModel):
    """Structured output of :meth:`LLMProvider.extract`.

    Holds only what the LLM is responsible for: TTPs, the attributed actor and
    the targeted sectors. Indicators are intentionally absent — they come from
    the regex parser in the ingestion pipeline.
    """

    ttps: list[TTP] = Field(default_factory=list)
    actor: str | None = None
    target_sectors: list[str] = Field(default_factory=list)


class LLMProvider(ABC):
    """Abstract, swappable interface to an AI backend.

    Concrete subclasses are selected at runtime from configuration (see
    ``LLMSettings.provider``).
    """

    @abstractmethod
    def extract(self, text: str) -> ExtractionResult:
        """Extract TTPs, actor and target sectors from unstructured ``text``.

        Complements the deterministic regex parser by recovering context that
        patterns cannot. It does **not** return IOCs.
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
    def narrate(self, subgraph: Subgraph) -> str:
        """Write a human-readable narrative explaining a correlation result.

        Takes an already-computed correlation ``Subgraph`` and produces an
        on-demand textual summary grounded solely in that evidence. Called only
        from the narrative endpoint, so cost scales with use, not data volume.
        """
        raise NotImplementedError
