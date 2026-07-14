// Side panel with the selected node's details. Two on-demand, kind-specific
// actions hang off it: IOC nodes can request an AI narrative; campaign nodes can
// fetch their semantic neighbours (both gracefully report when the corresponding
// backend is disabled, e.g. the no-keys demo).

import { useEffect, useState } from "react";
import { similar } from "../api/client";
import { describeError } from "../api/errors";
import type { GraphNode, SimilarNeighbor } from "../api/types";
import { useNarrative } from "../hooks/useNarrative";
import { NarrativePanel } from "./NarrativePanel";

interface NodeDetailPanelProps {
  node: GraphNode;
  onClose: () => void;
}

interface SimilarState {
  data: SimilarNeighbor[] | null;
  loading: boolean;
  error: string | null;
}

const IDLE_SIMILAR: SimilarState = { data: null, loading: false, error: null };

export function NodeDetailPanel({ node, onClose }: NodeDetailPanelProps) {
  const narrative = useNarrative();
  const [similarState, setSimilarState] = useState<SimilarState>(IDLE_SIMILAR);

  // Reset on-demand results whenever the selected node changes.
  useEffect(() => {
    narrative.clear();
    setSimilarState(IDLE_SIMILAR);
  }, [node.id, narrative.clear]);

  const loadSimilar = async () => {
    setSimilarState({ data: null, loading: true, error: null });
    try {
      const neighbours = await similar(node.id);
      setSimilarState({ data: neighbours, loading: false, error: null });
    } catch (err) {
      setSimilarState({
        data: null,
        loading: false,
        error: describeError(err, {
          disabled: "Semantic similarity is disabled on this server (no vector backend).",
          notFound: "No embedding is stored for this entity.",
        }),
      });
    }
  };

  return (
    <aside className="detail">
      <header className="detail__header">
        <span className={`detail__badge detail__badge--${node.kind}`}>{node.kind}</span>
        <button className="detail__close" onClick={onClose} aria-label="Close panel">
          ×
        </button>
      </header>

      <h2 className="detail__label">{node.label}</h2>
      <p className="detail__id">{node.id}</p>

      {node.kind === "ioc" && <NarrativePanel ioc={node.label} narrative={narrative} />}

      {node.kind === "campaign" && (
        <section className="detail__section">
          <div className="detail__section-head">
            <h3 className="detail__section-title">Similar campaigns</h3>
            <button
              className="detail__action"
              onClick={loadSimilar}
              disabled={similarState.loading}
            >
              {similarState.loading ? "Loading…" : "Find similar"}
            </button>
          </div>

          {similarState.error && <p className="detail__error">{similarState.error}</p>}

          {similarState.data && similarState.data.length === 0 && (
            <p className="detail__hint">No semantically similar campaigns found.</p>
          )}

          {similarState.data && similarState.data.length > 0 && (
            <ul className="detail__list">
              {similarState.data.map((neighbour) => (
                <li key={neighbour.id} className="detail__list-item">
                  <span>{neighbour.label ?? neighbour.id}</span>
                  <span className="detail__score">{neighbour.score.toFixed(2)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <p className="detail__hint detail__hint--muted">
        Double-click this node in the graph to expand its relationships.
      </p>
    </aside>
  );
}
