// Cytoscape styling. Colours live only in the CSS token layer (:root); this
// module reads them with getComputedStyle so there is no duplicated hex. The
// whole graph stays inside the warm-red brand ramp — kinds that are close in hue
// are additionally separated by shape and size — and semantic-similarity edges
// (the only AI-derived, weighted relation) are dashed and carry their cosine
// score so they never blend in with the deterministic structural edges.

import type cytoscape from "cytoscape";
import type { GraphEdge, GraphNode, NodeKind, Subgraph } from "../api/types";

// Read a CSS custom property from :root, with a fallback for non-DOM contexts.
function token(name: string, fallback: string): string {
  if (typeof document === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name);
  return value.trim() || fallback;
}

// Shape and size per kind (not colours, so not tokens). These keep IOC/Campaign/
// Actor distinguishable even though all three are reds.
const KIND_SHAPE: Record<NodeKind, string> = {
  ioc: "ellipse",
  campaign: "round-rectangle",
  actor: "hexagon",
  ttp: "diamond",
  sector: "triangle",
};

const KIND_SIZE: Record<NodeKind, number> = {
  ioc: 26,
  campaign: 32,
  actor: 34,
  ttp: 26,
  sector: 26,
};

const KIND_TOKEN: Record<NodeKind, string> = {
  ioc: "--kind-ioc",
  campaign: "--kind-campaign",
  actor: "--kind-actor",
  ttp: "--kind-ttp",
  sector: "--kind-sector",
};

export function elementsFromSubgraph(subgraph: Subgraph): cytoscape.ElementDefinition[] {
  const nodes = subgraph.nodes.map((node: GraphNode) => ({
    data: { id: node.id, label: node.label, kind: node.kind },
  }));
  const edges = subgraph.edges.map((edge: GraphEdge) => ({
    data: {
      id: `${edge.source} ${edge.type} ${edge.target}`,
      source: edge.source,
      target: edge.target,
      type: edge.type,
      label:
        edge.type === "semantic_similarity" && edge.score != null
          ? edge.score.toFixed(2)
          : "",
    },
  }));
  return [...nodes, ...edges];
}

// Built lazily (not at import time) so the CSS tokens are guaranteed applied.
export function buildStylesheet(): cytoscape.StylesheetStyle[] {
  const kinds: NodeKind[] = ["ioc", "campaign", "actor", "ttp", "sector"];

  const perKind = kinds.map((kind) => ({
    selector: `node[kind = "${kind}"]`,
    style: {
      "background-color": token(KIND_TOKEN[kind], "#ff5c5c"),
      shape: KIND_SHAPE[kind],
      width: KIND_SIZE[kind],
      height: KIND_SIZE[kind],
    },
  })) as cytoscape.StylesheetStyle[];

  const sheet: cytoscape.StylesheetStyle[] = [
    {
      selector: "node",
      style: {
        "background-color": token("--kind-ioc", "#ff5c5c"),
        label: "data(label)",
        color: token("--label-color", "#eef1f6"),
        "text-outline-color": token("--label-outline", "#0e0f13"),
        "text-outline-width": 2,
        "font-size": "10px",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 5,
        "text-wrap": "ellipsis",
        "text-max-width": "120px",
        width: 26,
        height: 26,
        "border-width": 2,
        "border-color": token("--node-border", "#0e0f13"),
        "transition-property":
          "background-color, border-color, border-width, underlay-opacity",
        // Cytoscape wants a unit-bearing time string at runtime, but the (older)
        // typings declare this as number; the cast keeps both happy.
        "transition-duration": "0.14s" as unknown as number,
      },
    },
    ...perKind,
    {
      // Deep-crimson actor gets a light rim so it reads on the dark canvas.
      selector: 'node[kind = "actor"]',
      style: {
        "border-color": token("--node-border-actor", "#ff5c5c"),
        "border-width": 2.5,
      },
    },
    {
      selector: "node.hover",
      style: {
        "underlay-color": token("--node-halo", "#e84850"),
        "underlay-opacity": 0.25,
        "underlay-padding": 6,
      },
    },
    {
      selector: "node.selected",
      style: {
        "border-color": token("--node-selected", "#ffffff"),
        "border-width": 4,
        "underlay-color": token("--node-halo", "#e84850"),
        "underlay-opacity": 0.35,
        "underlay-padding": 8,
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": token("--edge", "#6b585b"),
        "target-arrow-color": token("--edge", "#6b585b"),
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.8,
        label: "data(label)",
        "font-size": "8px",
        color: token("--label-color", "#eef1f6"),
        "text-outline-color": token("--label-outline", "#0e0f13"),
        "text-outline-width": 2,
      },
    },
    {
      selector: 'edge[type = "semantic_similarity"]',
      style: {
        "line-style": "dashed",
        "line-color": token("--edge-semantic", "#ff6f91"),
        "target-arrow-color": token("--edge-semantic", "#ff6f91"),
      },
    },
  ];

  return sheet;
}
