// Cytoscape graph canvas. Single click selects a node (drives the detail panel);
// double click expands it (fetches its neighbourhood and merges it in).
//
// Layout is managed manually rather than via the component's `layout` prop: the
// prop would re-run the force layout on every React render (each render passes a
// fresh `elements` array), reshuffling the graph even on a simple selection. So
// `elements` is memoised on a signature of the graph contents, and the layout is
// re-run only when that signature changes (a search or an expand).

import { useEffect, useMemo, useRef } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";
import type { Subgraph } from "../api/types";
import { buildStylesheet, elementsFromSubgraph } from "../graph/style";

interface GraphViewProps {
  graph: Subgraph;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onExpand: (id: string) => void;
}

const DOUBLE_TAP_MS: number = 300;

const LAYOUT: cytoscape.LayoutOptions = {
  name: "cose",
  animate: false,
  padding: 40,
  nodeRepulsion: () => 12000,
} as cytoscape.LayoutOptions;

export function GraphView({ graph, selectedId, onSelect, onExpand }: GraphViewProps) {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const lastTap = useRef<{ id: string; time: number }>({ id: "", time: 0 });
  // Keep the latest callbacks reachable from the once-registered event handlers.
  const handlers = useRef({ onSelect, onExpand });
  handlers.current = { onSelect, onExpand };

  // Built once, after the CSS tokens it reads are applied to the document.
  const stylesheet = useMemo(() => buildStylesheet(), []);

  // A signature of the graph contents; changes only on search/expand, not on
  // selection. Drives both element memoisation and layout re-runs.
  const signature = useMemo(
    () => graph.nodes.map((n) => n.id).join("|") + "#" + graph.edges.length,
    [graph],
  );
  const elements = useMemo(() => elementsFromSubgraph(graph), [signature]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.elements().length === 0) return;
    cy.layout(LAYOUT).run();
    cy.fit(undefined, 40);
  }, [signature]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass("selected");
    if (selectedId) cy.getElementById(selectedId).addClass("selected");
  }, [selectedId, signature]);

  const registerCy = (cy: cytoscape.Core) => {
    if (cyRef.current === cy) return; // react-cytoscapejs reuses one instance
    cyRef.current = cy;
    cy.on("tap", "node", (event) => {
      const id = event.target.id();
      const now = Date.now();
      handlers.current.onSelect(id);
      const previous = lastTap.current;
      if (previous.id === id && now - previous.time < DOUBLE_TAP_MS) {
        handlers.current.onExpand(id);
        lastTap.current = { id: "", time: 0 };
      } else {
        lastTap.current = { id, time: now };
      }
    });

    // Hover feedback: a red halo on the node and a pointer cursor.
    cy.on("mouseover", "node", (event) => {
      event.target.addClass("hover");
      cy.container()?.style.setProperty("cursor", "pointer");
    });
    cy.on("mouseout", "node", (event) => {
      event.target.removeClass("hover");
      cy.container()?.style.setProperty("cursor", "default");
    });
  };

  return (
    <CytoscapeComponent
      className="graphview"
      elements={elements}
      stylesheet={stylesheet}
      cy={registerCy}
      style={{ width: "100%", height: "100%" }}
    />
  );
}
