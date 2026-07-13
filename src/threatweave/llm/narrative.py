"""Prompt, evidence formatting and safeguards for on-demand narratives.

Provider-agnostic so any ``LLMProvider`` can reuse it. The narrative is grounded
**only** in the correlated subgraph: the model receives a deterministic evidence
block and nothing else, and a disclaimer is appended by code (not left to the
model) so the output is always marked as indicative.
"""

from __future__ import annotations

from threatweave.models.graph import Subgraph

NARRATIVE_SYSTEM_PROMPT = (
    "You are a cyber threat intelligence analyst assistant. You are given the "
    "EVIDENCE of a correlated subgraph: nodes (indicators, campaigns, actors, "
    "TTPs, sectors) and the relationships between them.\n\n"
    "Write a concise, clear explanation of why these entities appear to belong "
    "to the same campaign or activity. Cite the specific nodes and relationships "
    "from the evidence as support.\n\n"
    "STRICT RULES:\n"
    "- Use ONLY the entities and relationships in the evidence. Do NOT introduce "
    "any IOC, actor, TTP or attribution that is not present.\n"
    "- Do NOT speculate beyond what the relationships state. If evidence is thin, "
    "say so plainly.\n"
    "- Refer to indicators by their exact values as given.\n"
    "- Be factual and neutral; this is a lead for an analyst, not a conclusion."
)

# Appended programmatically to every narrative so the caveat is guaranteed.
DISCLAIMER = (
    "This narrative is AI-generated and indicative only. It is derived solely "
    "from correlated graph data and requires verification by a human analyst "
    "before being used for attribution or action."
)


def format_evidence(subgraph: Subgraph) -> str:
    """Render a subgraph as a deterministic, plain-text evidence block."""
    lines: list[str] = ["NODES:"]
    for node in subgraph.nodes:
        lines.append(f"- [{node.kind}] {node.id} \"{node.label}\"")

    lines.append("")
    lines.append("RELATIONSHIPS:")
    if not subgraph.edges:
        lines.append("- (none)")
    for edge in subgraph.edges:
        suffix = "" if edge.score is None else f" (score={edge.score:.3f})"
        lines.append(f"- {edge.source} --{edge.type.value}{suffix}--> {edge.target}")

    return "\n".join(lines)


def build_messages(subgraph: Subgraph) -> list[dict[str, str]]:
    """Build the chat messages for a narrative request."""
    return [
        {"role": "system", "content": NARRATIVE_SYSTEM_PROMPT},
        {"role": "user", "content": format_evidence(subgraph)},
    ]


def finalize_narrative(text: str) -> str:
    """Attach the mandatory disclaimer to a model-produced narrative."""
    body = text.strip()
    if not body:
        return DISCLAIMER
    return f"{body}\n\n---\n{DISCLAIMER}"
