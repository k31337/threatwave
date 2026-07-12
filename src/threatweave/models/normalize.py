"""Deterministic normalization helpers for extracted entities.

Keeping these pure and rule-based (no AI) guarantees that the same real-world
concept maps to the same graph node regardless of surface wording — e.g. a
report saying "Finance" and another saying "financial services" both land on one
canonical sector node.
"""

from __future__ import annotations

import re

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# A small, extensible alias map collapsing common sector wordings to a canonical
# form. Intentionally conservative: only unambiguous synonyms.
_SECTOR_ALIASES: dict[str, str] = {
    "finance": "financial services",
    "financial": "financial services",
    "financials": "financial services",
    "banking": "financial services",
    "bank": "financial services",
    "gov": "government",
    "govt": "government",
    "health": "healthcare",
    "health care": "healthcare",
    "telecom": "telecommunications",
    "telecoms": "telecommunications",
    "energy sector": "energy",
}


def normalize_technique_id(value: str) -> str:
    """Return a canonical MITRE ATT&CK technique id, or "" if malformed.

    Accepts ``T#### `` and sub-techniques ``T####.###`` (case-insensitive),
    returning the upper-cased id. Anything else is rejected so junk never becomes
    a TTP node.
    """
    candidate = value.strip().upper()
    return candidate if _TECHNIQUE_RE.match(candidate) else ""


def normalize_sector(name: str) -> str:
    """Return a canonical, lower-cased sector name (empty if blank).

    Whitespace is collapsed and a small alias map is applied. The result is used
    both as the sector node id key and, title-cased, as its display label.
    """
    collapsed = " ".join(name.strip().lower().split())
    if not collapsed:
        return ""
    return _SECTOR_ALIASES.get(collapsed, collapsed)


def sector_display(canonical: str) -> str:
    """Return a human-readable label for a canonical sector name."""
    return canonical.title()
