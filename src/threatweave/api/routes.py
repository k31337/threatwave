"""HTTP routes for the ThreatWeave API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from threatweave.correlation.correlate import correlate
from threatweave.graph.base import GraphStore
from threatweave.models.graph import Subgraph

router = APIRouter()


def _store(request: Request) -> GraphStore:
    """Return the graph store attached to the running application."""
    return request.app.state.store


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.get("/api/correlate", response_model=Subgraph)
def get_correlate(
    request: Request,
    ioc: str = Query(..., description="Indicator value: IP, domain, hash or URL."),
    depth: int = Query(1, ge=1, le=4, description="Relationship hops to include."),
) -> Subgraph:
    """Return the correlation subgraph for an indicator.

    Responds 404 when the indicator is not present in the graph.
    """
    subgraph = correlate(_store(request), ioc, depth=depth)
    if not subgraph.nodes:
        raise HTTPException(status_code=404, detail=f"IOC not found in graph: {ioc}")
    return subgraph
