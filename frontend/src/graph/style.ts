// Cytoscape stylesheet and element conversion. Colours encode the node kind and
// relationship type so the graph is readable at a glance; semantic-similarity
// edges (the only AI-derived, weighted relation) are visually distinct — dashed
// and carrying their cosine score — so they never blend in with the
// deterministic structural edges.

import type cytoscape from "cytoscape";
import type { GraphEdge, GraphNode, NodeKind, Subgraph } from "../api/types";

export const KIND_COLOR: Record<NodeKind, string> = {
  ioc: "#4f9cff",
  campaign: "#f0883e",
  actor: "#e5534b",
  ttp: "#a371f7",
  sector: "#3fb950",
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
      // Show the cosine score on semantic edges, blank on structural ones.
      label:
        edge.type === "semantic_similarity" && edge.score != null
          ? edge.score.toFixed(2)
          : "",
    },
  }));
  return [...nodes, ...edges];
}

export const stylesheet: cytoscape.StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      "background-color": "#4f9cff",
      label: "data(label)",
      color: "#e6eaf2",
      "font-size": "10px",
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 4,
      "text-wrap": "ellipsis",
      "text-max-width": "120px",
      width: 26,
      height: 26,
      "border-width": 2,
      "border-color": "#0f1420",
    },
  },
  ...(Object.entries(KIND_COLOR).map(([kind, color]) => ({
    selector: `node[kind = "${kind}"]`,
    style: { "background-color": color },
  })) as cytoscape.StylesheetStyle[]),
  {
    selector: "node.selected",
    style: {
      "border-color": "#ffffff",
      "border-width": 4,
    },
  },
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": "#3a4459",
      "target-arrow-color": "#3a4459",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.8,
      label: "data(label)",
      "font-size": "8px",
      color: "#9aa6bd",
    },
  },
  {
    selector: 'edge[type = "semantic_similarity"]',
    style: {
      "line-style": "dashed",
      "line-color": "#a371f7",
      "target-arrow-color": "#a371f7",
    },
  },
];
