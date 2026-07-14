// Application shell: search + interactive graph + selected-node detail panel,
// with graph-level loading/error surfaced by a floating status banner.

import { GraphView } from "./components/GraphView";
import { NodeDetailPanel } from "./components/NodeDetailPanel";
import { SearchBar } from "./components/SearchBar";
import { StatusBanner } from "./components/StatusBanner";
import { useGraph } from "./hooks/useGraph";

export function App() {
  const { graph, selectedId, loading, error, search, expandNode, select } = useGraph();
  const hasGraph = graph.nodes.length > 0;
  const selectedNode = graph.nodes.find((node) => node.id === selectedId) ?? null;

  return (
    <div className="app">
      <header className="app__header">
        <div>
          <h1 className="app__title">ThreatWeave</h1>
          <p className="app__tagline">Deterministic threat-intelligence graph explorer</p>
        </div>
        <SearchBar onSearch={search} loading={loading} />
      </header>

      <main className="app__main">
        <div className="app__graph">
          {hasGraph ? (
            <GraphView
              graph={graph}
              selectedId={selectedId}
              onSelect={select}
              onExpand={expandNode}
            />
          ) : (
            <div className="app__empty">
              <p>Search an indicator to build its correlation graph.</p>
              <p className="app__hint">
                Try <code>malicious.example</code> or <code>203.0.113.10</code>. Click a
                node to select it, double-click to expand its relationships.
              </p>
            </div>
          )}
          <StatusBanner loading={loading} error={error} />
        </div>

        {selectedNode && (
          <NodeDetailPanel node={selectedNode} onClose={() => select(null)} />
        )}
      </main>
    </div>
  );
}
