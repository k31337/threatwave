"""Tests for the in-memory GraphStore (contract shared with the Neo4j backend)."""

from __future__ import annotations

import pytest

from threatweave.graph.memory import InMemoryGraphStore
from threatweave.models.graph import RelationType, ioc_node_id
from threatweave.models.ioc import IOC, Actor, Campaign, IOCType


def _ioc(value: str, ioc_type: IOCType) -> IOC:
    return IOC(value=value, type=ioc_type)


def test_upsert_is_idempotent() -> None:
    store = InMemoryGraphStore()
    ioc = _ioc("8.8.8.8", IOCType.IPV4)

    first = store.upsert_ioc(ioc)
    second = store.upsert_ioc(ioc)

    assert first.id == second.id
    assert store.get_node(ioc_node_id(ioc)) is not None


def test_get_node_missing_returns_none() -> None:
    assert InMemoryGraphStore().get_node("ioc:ipv4:1.1.1.1") is None


def test_add_edge_requires_existing_nodes() -> None:
    store = InMemoryGraphStore()
    store.upsert_ioc(_ioc("1.2.3.4", IOCType.IPV4))

    with pytest.raises(KeyError):
        store.add_edge("ioc:ipv4:1.2.3.4", "ioc:domain:evil.com", RelationType.RESOLVES_TO)


def test_neighborhood_of_unknown_node_is_empty() -> None:
    sub = InMemoryGraphStore().neighborhood("ioc:ipv4:9.9.9.9")
    assert sub.nodes == []
    assert sub.edges == []


def test_neighborhood_single_hop() -> None:
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    domain = _ioc("evil.com", IOCType.DOMAIN)
    store.upsert_ioc(ip)
    store.upsert_ioc(domain)
    store.add_edge(ioc_node_id(domain), ioc_node_id(ip), RelationType.RESOLVES_TO)

    sub = store.neighborhood(ioc_node_id(ip), depth=1)

    node_ids = {n.id for n in sub.nodes}
    assert node_ids == {ioc_node_id(ip), ioc_node_id(domain)}
    assert len(sub.edges) == 1
    assert sub.edges[0].type is RelationType.RESOLVES_TO


def test_neighborhood_respects_depth() -> None:
    # Chain: ip -- domain -- actor. From ip, depth=1 sees domain only; depth=2
    # also reaches the actor.
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    domain = _ioc("evil.com", IOCType.DOMAIN)
    store.upsert_ioc(ip)
    store.upsert_ioc(domain)
    store.upsert_actor(Actor(name="APT-Test"))
    store.add_edge(ioc_node_id(domain), ioc_node_id(ip), RelationType.RESOLVES_TO)
    store.add_edge(ioc_node_id(domain), "actor:APT-Test", RelationType.ATTRIBUTED_TO)

    depth1 = {n.id for n in store.neighborhood(ioc_node_id(ip), depth=1).nodes}
    assert "actor:APT-Test" not in depth1

    depth2 = {n.id for n in store.neighborhood(ioc_node_id(ip), depth=2).nodes}
    assert "actor:APT-Test" in depth2


def test_neighborhood_traversal_is_undirected() -> None:
    # Edge domain -> ip; querying from the ip (the target) must still reach it.
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    domain = _ioc("evil.com", IOCType.DOMAIN)
    store.upsert_ioc(ip)
    store.upsert_ioc(domain)
    store.add_edge(ioc_node_id(domain), ioc_node_id(ip), RelationType.RESOLVES_TO)

    reachable = {n.id for n in store.neighborhood(ioc_node_id(ip), depth=1).nodes}
    assert ioc_node_id(domain) in reachable


def test_campaign_node_kind() -> None:
    store = InMemoryGraphStore()
    node = store.upsert_campaign(Campaign(name="Op-Test"))
    assert node.kind == "campaign"
    assert node.label == "Op-Test"


# --- Batch writes ---


def test_upsert_iocs_writes_all_and_returns_nodes() -> None:
    store = InMemoryGraphStore()
    iocs = [_ioc("1.2.3.4", IOCType.IPV4), _ioc("evil.com", IOCType.DOMAIN)]

    nodes = store.upsert_iocs(iocs)

    assert {n.id for n in nodes} == {ioc_node_id(iocs[0]), ioc_node_id(iocs[1])}
    assert all(store.get_node(n.id) is not None for n in nodes)


def test_upsert_iocs_is_idempotent_and_dedups() -> None:
    store = InMemoryGraphStore()
    ioc = _ioc("8.8.8.8", IOCType.IPV4)

    # Duplicates within one batch collapse to a single node...
    first = store.upsert_iocs([ioc, ioc])
    assert [n.id for n in first] == [ioc_node_id(ioc)]

    # ...and re-running the batch does not duplicate anything.
    store.upsert_iocs([ioc])
    assert len(store.neighborhood(ioc_node_id(ioc)).nodes) == 1


def test_upsert_iocs_empty_is_noop() -> None:
    assert InMemoryGraphStore().upsert_iocs([]) == []


def test_add_edges_writes_batch() -> None:
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    domain = _ioc("evil.com", IOCType.DOMAIN)
    store.upsert_campaign(Campaign(name="Op-Test"))
    store.upsert_iocs([ip, domain])

    store.add_edges(
        [
            (ioc_node_id(ip), "campaign:Op-Test", RelationType.PART_OF),
            (ioc_node_id(domain), "campaign:Op-Test", RelationType.PART_OF),
        ]
    )

    sub = store.neighborhood("campaign:Op-Test", depth=1)
    assert {n.id for n in sub.nodes} == {
        "campaign:Op-Test",
        ioc_node_id(ip),
        ioc_node_id(domain),
    }
    assert len(sub.edges) == 2


def test_add_edges_is_all_or_nothing_on_unknown_node() -> None:
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    store.upsert_iocs([ip])

    with pytest.raises(KeyError):
        store.add_edges(
            [
                (ioc_node_id(ip), "campaign:Missing", RelationType.PART_OF),
            ]
        )

    # The valid-looking endpoint gained no edges: the batch was rejected wholesale.
    assert store.neighborhood(ioc_node_id(ip)).edges == []


def test_add_edges_is_idempotent() -> None:
    store = InMemoryGraphStore()
    ip = _ioc("1.2.3.4", IOCType.IPV4)
    store.upsert_campaign(Campaign(name="Op-Test"))
    store.upsert_iocs([ip])
    edge = (ioc_node_id(ip), "campaign:Op-Test", RelationType.PART_OF)

    store.add_edges([edge])
    store.add_edges([edge])

    assert len(store.neighborhood("campaign:Op-Test").edges) == 1
