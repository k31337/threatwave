"""HTTP routes for the ThreatWeave API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from threatweave.api.security import limiter, rate_limit, require_api_key
from threatweave.config import get_settings
from threatweave.correlation.correlate import correlate
from threatweave.correlation.similar import similar
from threatweave.graph.base import GraphStore
from threatweave.ingest_state import IngestState, SourceState
from threatweave.llm.base import LLMProvider
from threatweave.models.graph import Subgraph
from threatweave.vector.base import VectorStore

router = APIRouter()

# Applied to every /api/* route: casual API-key gating plus a per-client rate
# limit. /health is intentionally left open as an unauthenticated liveness probe.
_api_deps = [Depends(require_api_key)]


def _store(request: Request) -> GraphStore:
    """Return the graph store attached to the running application."""
    return request.app.state.store


def _vector_store(request: Request) -> VectorStore | None:
    """Return the vector store, or ``None`` when semantic search is disabled."""
    return request.app.state.vector_store


def _provider(request: Request) -> LLMProvider | None:
    """Return the LLM provider, or ``None`` when none is configured."""
    return request.app.state.provider


class SimilarNeighbor(BaseModel):
    """One semantic neighbour returned by ``/api/similar``."""

    id: str
    label: str | None
    score: float


class NarrativeResponse(BaseModel):
    """Response of ``/api/narrative``."""

    ioc: str
    narrative: str
    model: str


class IngestStatusResponse(BaseModel):
    """Response of ``/api/ingest/status``: the last run per source."""

    sources: list[SourceState]


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/api/correlate", response_model=Subgraph, dependencies=_api_deps)
@limiter.limit(rate_limit)
def get_correlate(
    request: Request,
    ioc: str = Query(..., description="Indicator value: IP, domain, hash or URL."),
    depth: int = Query(1, ge=1, le=4, description="Relationship hops to include."),
    semantic: bool = Query(False, description="Also include semantic-similarity edges."),
    k: int = Query(5, ge=1, le=50, description="Max semantic neighbours per campaign."),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Min cosine score."),
) -> Subgraph:
    """Return the correlation subgraph for an indicator.

    With ``semantic=true`` (and a vector backend configured), the result also
    includes ``semantic_similarity`` edges. Responds 404 when the indicator is
    not present in the graph.
    """
    vector_store = _vector_store(request) if semantic else None
    subgraph = correlate(
        _store(request), ioc, depth=depth, vector_store=vector_store, k=k, min_score=min_score
    )
    if not subgraph.nodes:
        raise HTTPException(status_code=404, detail=f"IOC not found in graph: {ioc}")
    return subgraph


@router.get("/api/expand", response_model=Subgraph, dependencies=_api_deps)
@limiter.limit(rate_limit)
def get_expand(
    request: Request,
    id: str = Query(..., description="Node id to expand, e.g. 'campaign:<name>'."),
    depth: int = Query(1, ge=1, le=4, description="Relationship hops to include."),
) -> Subgraph:
    """Return the neighbourhood subgraph around an arbitrary node.

    This powers graph exploration in the UI: unlike ``/api/correlate`` (which
    resolves a raw IOC *value*), ``expand`` takes any node id — IOC, campaign,
    actor, TTP or sector — and returns its neighbourhood. It is purely
    deterministic graph traversal (``GraphStore.neighborhood``), identical across
    the memory and Neo4j backends; no AI is involved. Responds 404 when the node
    is not in the graph.
    """
    store = _store(request)
    if store.get_node(id) is None:
        raise HTTPException(status_code=404, detail=f"node not found: {id}")
    return store.neighborhood(id, depth=depth)


@router.get("/api/similar", response_model=list[SimilarNeighbor], dependencies=_api_deps)
@limiter.limit(rate_limit)
def get_similar(
    request: Request,
    id: str = Query(..., description="Entity id, e.g. 'campaign:<name>'."),
    k: int = Query(5, ge=1, le=50, description="Number of neighbours to return."),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Min cosine score."),
) -> list[SimilarNeighbor]:
    """Return the ``k`` most semantically similar entities to ``id``.

    Responds 503 if semantic search is disabled, or 404 if the entity has no
    stored embedding.
    """
    vector_store = _vector_store(request)
    if vector_store is None:
        raise HTTPException(
            status_code=503,
            detail="semantic similarity is disabled (set VECTOR_BACKEND)",
        )
    if vector_store.get(id) is None:
        raise HTTPException(status_code=404, detail=f"no embedding for entity: {id}")

    store = _store(request)
    neighbors = similar(vector_store, id, k=k, min_score=min_score)
    return [
        SimilarNeighbor(
            id=neighbor.id,
            label=(node.label if (node := store.get_node(neighbor.id)) else None),
            score=neighbor.score,
        )
        for neighbor in neighbors
    ]


@router.get("/api/narrative", response_model=NarrativeResponse, dependencies=_api_deps)
@limiter.limit(rate_limit)
def get_narrative(
    request: Request,
    ioc: str = Query(..., description="Indicator value: IP, domain, hash or URL."),
    depth: int = Query(1, ge=1, le=4, description="Relationship hops to include."),
    semantic: bool = Query(False, description="Also consider semantic-similarity edges."),
    k: int = Query(5, ge=1, le=50, description="Max semantic neighbours per campaign."),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Min cosine score."),
) -> NarrativeResponse:
    """Generate an on-demand natural-language narrative for an indicator.

    Computes the correlation subgraph with the existing deterministic logic, then
    asks the LLM to explain it — grounded solely in that subgraph. This is the
    only place narratives are generated, so cost scales with use, not data
    volume. Responds 404 if the indicator is absent, 503 if no LLM is configured.
    """
    provider = _provider(request)
    if provider is None:
        raise HTTPException(
            status_code=503,
            detail="narrative generation is disabled (no LLM provider configured)",
        )

    vector_store = _vector_store(request) if semantic else None
    subgraph = correlate(
        _store(request), ioc, depth=depth, vector_store=vector_store, k=k, min_score=min_score
    )
    if not subgraph.nodes:
        raise HTTPException(status_code=404, detail=f"IOC not found in graph: {ioc}")

    narrative = provider.narrate(subgraph)
    model = getattr(provider, "narrative_model", None) or get_settings().llm.narrative_model
    return NarrativeResponse(ioc=ioc, narrative=narrative, model=model)


@router.get("/api/ingest/status", response_model=IngestStatusResponse, dependencies=_api_deps)
@limiter.limit(rate_limit)
def get_ingest_status(request: Request) -> IngestStatusResponse:
    """Return the last ingestion outcome for each source.

    Reads the persistent ingest-state file (written by ``threatweave ingest``,
    typically in a separate cron/scheduler process), so it reflects the most
    recent run: when it ran, how many IOCs it wrote, and any error. Sources that
    have never run simply do not appear. This is pure observability — no graph or
    AI access.
    """
    state = IngestState(get_settings().ingest_state_path)
    sources = sorted(state.snapshot().sources.values(), key=lambda s: s.source)
    return IngestStatusResponse(sources=sources)
