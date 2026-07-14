// Transport types mirroring the ThreatWeave API (see src/threatweave/models/graph.py
// and the /api routes). Kept in sync by hand — the API is small and stable.

export type NodeKind = "ioc" | "actor" | "campaign" | "ttp" | "sector";

export type RelationType =
  | "related_to"
  | "attributed_to"
  | "part_of"
  | "resolves_to"
  | "communicates_with"
  | "uses"
  | "targets"
  | "semantic_similarity";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: RelationType;
  // Set only for weighted edges (semantic similarity carries a cosine score).
  score?: number | null;
}

export interface Subgraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SimilarNeighbor {
  id: string;
  label: string | null;
  score: number;
}

export interface Narrative {
  ioc: string;
  narrative: string;
  model: string;
}
