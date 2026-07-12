"""Free-text / URL ingestion connector with hybrid extraction.

Given a URL or raw text, this connector produces a :class:`DocumentIntel`: the
deterministic IOCs from the regex parser **and** the LLM-extracted TTPs, actor
and target sectors. This is where the hybrid split lives — regex owns the
indicators (zero tokens), the LLM owns the context — so the two never duplicate
work.
"""

from __future__ import annotations

import logging
from html.parser import HTMLParser

import httpx
from pydantic import BaseModel, Field

from threatweave.llm.base import ExtractionResult, LLMProvider
from threatweave.models.ioc import IOC
from threatweave.parsers.ioc_parser import parse_iocs

logger = logging.getLogger(__name__)

# Tags whose text content is not human-readable report prose.
_SKIP_TAGS = {"script", "style", "head", "noscript", "template"}


class _HTMLTextExtractor(HTMLParser):
    """Collect visible text and the document title from HTML using stdlib only."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._title_parts: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                self._chunks.append(stripped)

    @property
    def title(self) -> str:
        return " ".join("".join(self._title_parts).split())

    @property
    def text(self) -> str:
        return "\n".join(self._chunks)


def html_to_text(html: str) -> tuple[str, str]:
    """Return ``(title, text)`` extracted from an HTML document."""
    parser = _HTMLTextExtractor()
    parser.feed(html)
    return parser.title, parser.text


class DocumentIntel(BaseModel):
    """Combined output of a document ingestion: regex IOCs + LLM extraction.

    ``text`` is the (possibly truncated) content that was analysed; it is the
    basis for the document's embedding at ingestion time.
    """

    report_name: str
    source: str
    text: str = ""
    iocs: list[IOC] = Field(default_factory=list)
    extraction: ExtractionResult = Field(default_factory=ExtractionResult)


def _derive_name(text: str, fallback: str) -> str:
    """Use the first non-empty line as a report name, falling back if empty."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:120]
    return fallback


class DocumentConnector:
    """Turns unstructured documents into normalized intelligence."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        client: httpx.Client | None = None,
        max_input_chars: int = 48_000,
    ) -> None:
        """Create the connector.

        Args:
            provider: The LLM provider used for context extraction.
            client: Optional HTTP client for URL fetching (injected in tests).
            max_input_chars: Text longer than this is truncated before the LLM
                call to bound token cost. Regex parsing always sees the full text.
        """
        self._provider = provider
        self._client = client
        self._owns_client = client is None
        self._max_input_chars = max_input_chars

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0, follow_redirects=True)
        return self._client

    def from_text(
        self, text: str, *, name: str | None = None, source: str = "inline-text"
    ) -> DocumentIntel:
        """Extract intelligence from raw ``text``.

        IOCs are parsed from the full text; the (possibly truncated) text is sent
        to the LLM for TTP/actor/sector extraction.
        """
        iocs = parse_iocs(text, source=source)

        llm_input = text
        if len(text) > self._max_input_chars:
            logger.warning(
                "document %r truncated from %d to %d chars for the LLM call",
                source,
                len(text),
                self._max_input_chars,
            )
            llm_input = text[: self._max_input_chars]

        extraction = self._provider.extract(llm_input)
        report_name = name or _derive_name(text, fallback=source)
        return DocumentIntel(
            report_name=report_name,
            source=source,
            text=llm_input,
            iocs=iocs,
            extraction=extraction,
        )

    def from_url(self, url: str) -> DocumentIntel:
        """Fetch ``url`` and extract intelligence from its content."""
        response = self._http().get(url)
        response.raise_for_status()

        content_type = response.headers.get("content-type", "")
        if "html" in content_type.lower():
            title, text = html_to_text(response.text)
            name = title or url
        else:
            text = response.text
            name = url

        return self.from_text(text, name=name, source=url)

    def close(self) -> None:
        """Close the HTTP client if this connector created it."""
        if self._owns_client and self._client is not None:
            self._client.close()
