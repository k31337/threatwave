"""Token-usage cost estimation and logging for LLM calls.

Pricing is a best-effort convenience, not billing truth: it is a static table
that will drift as vendors change prices. It is therefore **tolerant** — an
unknown model yields a ``None`` cost and a warning, never an exception, so
extraction never fails just because a price is missing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# USD per 1M tokens, as (input, output). Update as needed; unknown models are
# handled gracefully.
_PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    # Embedding models bill input tokens only (no completion tokens).
    "text-embedding-3-small": (0.02, 0.00),
    "text-embedding-3-large": (0.13, 0.00),
}


@dataclass(frozen=True)
class Usage:
    """Token counts for a single LLM call."""

    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def estimate_cost(model: str, usage: Usage) -> float | None:
    """Return the estimated USD cost of a call, or ``None`` if the model price
    is unknown.
    """
    price = _PRICES_PER_MTOK.get(model)
    if price is None:
        logger.warning("no price table entry for model %r; cost unknown", model)
        return None
    input_price, output_price = price
    return (
        usage.prompt_tokens / 1_000_000 * input_price
        + usage.completion_tokens / 1_000_000 * output_price
    )


def log_usage(model: str, usage: Usage, *, document: str | None = None) -> float | None:
    """Log token usage and estimated cost for a call; return the cost estimate."""
    cost = estimate_cost(model, usage)
    cost_str = "unknown" if cost is None else f"${cost:.6f}"
    logger.info(
        "LLM usage model=%s document=%s prompt_tokens=%d completion_tokens=%d "
        "total_tokens=%d est_cost=%s",
        model,
        document or "-",
        usage.prompt_tokens,
        usage.completion_tokens,
        usage.total_tokens,
        cost_str,
    )
    return cost
