"""HTTP routes for the ThreatWeave API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from threatweave.correlation.correlate import correlate
from threatweave.correlation.similar import similar
from threatweave.graph.base import GraphStore
from threatweave.models.graph import Subgraph
from threatweave.vector.base import VectorStore

router = APIRouter()


def _store(request: Request) -> GraphStore:
    """Return the graph store attached to the running application."""
    return request.app.state.store


def _vector_store(request: Request) -> VectorStore | None:
    """Return the vector store, or ``None`` when semantic search is disabled."""
    return request.app.state.vector_store


class SimilarNeighbor(BaseModel):
    """One semantic neighbour returned by ``/api/similar``."""

    id: str
    label: str | None
    score: float


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/api/correlate", response_model=Subgraph)
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


@router.get("/api/similar", response_model=list[SimilarNeighbor])
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
