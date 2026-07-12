"""Tests for the OTX connector: normalization and the (mocked) HTTP path."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from threatweave.connectors.otx import OTXConnector, normalize_indicators
from threatweave.models.ioc import IOCType


def test_normalize_maps_all_supported_types(otx_payload: dict[str, Any]) -> None:
    iocs = normalize_indicators(otx_payload, source="alienvault-otx")
    by_type = {ioc.type for ioc in iocs}

    assert by_type == {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA256,
    }
    # "hostname" maps to DOMAIN, so both the domain and the hostname appear.
    domains = {ioc.value for ioc in iocs if ioc.type is IOCType.DOMAIN}
    assert domains == {"malicious.example", "c2.malicious.example"}


def test_normalize_skips_unsupported_types(otx_payload: dict[str, Any]) -> None:
    # The sample contains an "email" indicator that must be dropped.
    values = {ioc.value for ioc in normalize_indicators(otx_payload, source="x")}
    assert "operator@malicious.example" not in values


def test_normalize_sets_source_and_first_seen(otx_payload: dict[str, Any]) -> None:
    iocs = normalize_indicators(otx_payload, source="alienvault-otx")
    assert all(ioc.source == "alienvault-otx" for ioc in iocs)
    ip = next(ioc for ioc in iocs if ioc.type is IOCType.IPV4)
    assert ip.first_seen == datetime.fromisoformat("2026-01-05T10:00:00")


def test_hashes_are_lowercased() -> None:
    payload = {
        "results": [
            {
                "indicators": [
                    {"type": "FileHash-MD5", "indicator": "D41D8CD98F00B204E9800998ECF8427E"}
                ]
            }
        ]
    }
    iocs = normalize_indicators(payload, source="x")
    assert iocs[0].value == "d41d8cd98f00b204e9800998ecf8427e"


def test_fetch_iocs_over_mocked_http(otx_payload: dict[str, Any]) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["api_key"] = request.headers.get("X-OTX-API-KEY")
        return httpx.Response(200, json=otx_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = OTXConnector(
        api_key="test-key", base_url="https://otx.test/api/v1", client=client
    )

    iocs = connector.fetch_iocs()

    assert len(iocs) == 6  # 7 indicators minus the unsupported email
    assert all(ioc.source == "alienvault-otx" for ioc in iocs)
    assert captured["api_key"] == "test-key"
    assert captured["url"].startswith("https://otx.test/api/v1/pulses/subscribed")
