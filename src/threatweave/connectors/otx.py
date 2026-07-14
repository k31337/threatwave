"""AlienVault OTX ingestion connector.

Pulls indicators from the OTX "subscribed pulses" endpoint and normalizes each
one into the internal :class:`IOC` model. Normalization is pure and deterministic
(a type-map lookup, no AI). The HTTP client is injectable so the connector can be
exercised offline against the synthetic sample in ``data/samples/``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from threatweave.connectors.base import Connector
from threatweave.models.ioc import IOC, IOCType

logger = logging.getLogger(__name__)

# Mapping from OTX indicator type strings to our internal IOC types. Types absent
# from this map (IPv6, email, CVE, YARA, ...) are not yet modelled and skipped.
_OTX_TYPE_MAP: dict[str, IOCType] = {
    "IPv4": IOCType.IPV4,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "URI": IOCType.URL,
    "FileHash-MD5": IOCType.MD5,
    "FileHash-SHA1": IOCType.SHA1,
    "FileHash-SHA256": IOCType.SHA256,
}


def _parse_created(value: str | None) -> datetime | None:
    """Best-effort parse of an OTX ``created`` timestamp into a datetime."""
    if not value:
        return None
    try:
        # Accept a trailing 'Z' (UTC) that fromisoformat rejects before 3.11.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("could not parse OTX timestamp: %r", value)
        return None


def normalize_indicators(payload: dict[str, Any], *, source: str) -> list[IOC]:
    """Normalize a raw OTX pulses payload into internal IOCs.

    Args:
        payload: The parsed JSON body of an OTX pulses response.
        source: Provenance label to stamp on every produced IOC.

    Returns:
        Deduplicated IOCs (by type and value). Indicators whose type is not in
        :data:`_OTX_TYPE_MAP` are skipped with a debug log.
    """
    seen: dict[tuple[IOCType, str], IOC] = {}
    for pulse in payload.get("results", []):
        for indicator in pulse.get("indicators", []):
            otx_type = indicator.get("type")
            value = indicator.get("indicator")
            if not value:
                continue
            ioc_type = _OTX_TYPE_MAP.get(otx_type)
            if ioc_type is None:
                logger.debug("skipping unsupported OTX indicator type: %r", otx_type)
                continue
            # Canonicalize the same way the regex parser does.
            normalized = value.lower() if ioc_type is not IOCType.URL else value
            key = (ioc_type, normalized)
            if key not in seen:
                seen[key] = IOC(
                    value=normalized,
                    type=ioc_type,
                    source=source,
                    first_seen=_parse_created(indicator.get("created")),
                )
    return sorted(seen.values(), key=lambda ioc: (ioc.type.value, ioc.value))


class OTXConnector(Connector):
    """Fetches and normalizes indicators from AlienVault OTX."""

    name = "alienvault-otx"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://otx.alienvault.com/api/v1",
        *,
        client: httpx.Client | None = None,
        page_limit: int = 50,
    ) -> None:
        """Create the connector.

        Args:
            api_key: OTX API key, sent in the ``X-OTX-API-KEY`` header.
            base_url: OTX API root.
            client: Optional pre-built HTTP client (injected in tests). When
                omitted, one is created lazily and owned by the connector.
            page_limit: Number of pulses to request per page.
        """
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._page_limit = page_limit
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def fetch_payload(self) -> dict[str, Any]:
        """Fetch the raw subscribed-pulses payload.

        Exposed so the scheduled ingest path can build campaign structure (and
        optionally embed pulse descriptions) from the full pulses, not just the
        flattened indicators returned by :meth:`fetch_iocs`.
        """
        response = self._http().get(
            f"{self._base_url}/pulses/subscribed",
            headers={"X-OTX-API-KEY": self._api_key},
            params={"limit": self._page_limit},
        )
        response.raise_for_status()
        return response.json()

    def fetch_iocs(self) -> list[IOC]:
        """Fetch subscribed pulses and return their normalized IOCs."""
        payload = self.fetch_payload()
        return normalize_indicators(payload, source=self.name)

    def close(self) -> None:
        """Close the HTTP client if this connector created it."""
        if self._owns_client and self._client is not None:
            self._client.close()
