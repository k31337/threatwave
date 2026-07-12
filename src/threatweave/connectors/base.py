"""The ``Connector`` port shared by all ingestion sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from threatweave.models.ioc import IOC


class Connector(ABC):
    """Abstract ingestion source.

    A connector knows how to reach one external feed and turn its response into
    normalized internal :class:`IOC` objects. Building the graph from those IOCs
    is a separate concern handled downstream.
    """

    #: Short, stable identifier used as IOC provenance.
    name: str = "connector"

    @abstractmethod
    def fetch_iocs(self) -> list[IOC]:
        """Fetch the latest indicators and return them normalized."""
