// Graph exploration state: run a search (correlate, replacing the graph), expand
// a node (merge its neighbourhood in), and track the current selection plus
// loading/error status. All correlation here is the API's deterministic graph
// logic — no AI is involved in building or growing the graph.

import { useCallback, useState } from "react";
import { correlate, expand } from "../api/client";
import { describeError } from "../api/errors";
import type { Subgraph } from "../api/types";
import { mergeSubgraphs } from "../graph/merge";

const EMPTY: Subgraph = { nodes: [], edges: [] };

export interface UseGraph {
  graph: Subgraph;
  selectedId: string | null;
  loading: boolean;
  error: string | null;
  search: (ioc: string) => Promise<void>;
  expandNode: (id: string) => Promise<void>;
  select: (id: string | null) => void;
  reset: () => void;
}

export function useGraph(): UseGraph {
  const [graph, setGraph] = useState<Subgraph>(EMPTY);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const search = useCallback(async (ioc: string) => {
    const value = ioc.trim();
    if (!value) return;
    setLoading(true);
    setError(null);
    try {
      const result = await correlate(value, { depth: 2 });
      setGraph(result);
      setSelectedId(null);
    } catch (err) {
      setGraph(EMPTY);
      setError(
        describeError(err, {
          notFound: `No indicator matching "${value}" is in the graph.`,
        }),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  const expandNode = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const neighbourhood = await expand(id, 1);
      setGraph((current) => mergeSubgraphs(current, neighbourhood));
    } catch (err) {
      setError(describeError(err, { notFound: "That node is no longer in the graph." }));
    } finally {
      setLoading(false);
    }
  }, []);

  const select = useCallback((id: string | null) => setSelectedId(id), []);

  const reset = useCallback(() => {
    setGraph(EMPTY);
    setSelectedId(null);
    setError(null);
  }, []);

  return { graph, selectedId, loading, error, search, expandNode, select, reset };
}
