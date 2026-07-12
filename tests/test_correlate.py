"""Tests for deterministic correlation and end-to-end ingest -> correlate."""

from __future__ import annotations

from typing import Any

from threatweave.correlation.correlate import correlate
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_otx_payload
from threatweave.models.graph import RelationType, ioc_node_id
from threatweave.models.ioc import IOC, IOCType


def _ioc(value: str, ioc_type: IOCType) -> IOC:
    return IOC(value=value, type=ioc_type)


def test_correlate_unknown_ioc_returns_empty(store: InMemoryGraphStore) -> None:
    assert correlate(store, "9.9.9.9").nodes == []


def test_correlate_resolves_type_from_value(store: InMemoryGraphStore) -> None:
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    domain = _ioc("evil.com", IOCType.DOMAIN)
    store.upsert_ioc(ip)
    store.upsert_ioc(domain)
    store.add_edge(ioc_node_id(domain), ioc_node_id(ip), RelationType.RESOLVES_TO)

    # Query by the raw IP string; correlate infers the type and finds the node.
    sub = correlate(store, "1.2.3.4", depth=1)
    assert {n.label for n in sub.nodes} == {"1.2.3.4", "evil.com"}


def test_ingest_then_correlate_finds_pulse_siblings(otx_payload: dict[str, Any]) -> None:
    store = InMemoryGraphStore()
    written = ingest_otx_payload(store, otx_payload)
    assert written == 6  # supported indicators in the sample

    # Query one indicator; at depth 2 the shared campaign links its siblings.
    sub = correlate(store, "203.0.113.10", depth=2)
    labels = {n.label for n in sub.nodes}

    assert "203.0.113.10" in labels
    assert "malicious.example" in labels  # sibling IOC via the campaign
    assert "Synthetic APT-Test Infrastructure" in labels  # the campaign node
    kinds = {n.kind for n in sub.nodes}
    assert "campaign" in kinds


def test_ingest_depth_one_stops_at_campaign(otx_payload: dict[str, Any]) -> None:
    store = InMemoryGraphStore()
    ingest_otx_payload(store, otx_payload)

    # At depth 1 from an IOC we reach the campaign but not sibling IOCs.
    sub = correlate(store, "203.0.113.10", depth=1)
    labels = {n.label for n in sub.nodes}
    assert "Synthetic APT-Test Infrastructure" in labels
    assert "malicious.example" not in labels


def test_correlate_prefers_most_specific_match(store: InMemoryGraphStore) -> None:
    # Both a URL and its host domain exist; querying the URL resolves the URL node.
    url = _ioc("http://malicious.example/payload.bin", IOCType.URL)
    domain = _ioc("malicious.example", IOCType.DOMAIN)
    store.upsert_ioc(url)
    store.upsert_ioc(domain)

    sub = correlate(store, "http://malicious.example/payload.bin", depth=0)
    assert [n.id for n in sub.nodes] == [ioc_node_id(url)]
