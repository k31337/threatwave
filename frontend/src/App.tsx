// Application shell. The interactive graph explorer (search, Cytoscape view,
// node detail + narrative) is layered on in the following commits; this scaffold
// establishes the layout and confirms the API client wiring compiles.

export function App() {
  return (
    <div className="app">
      <header className="app__header">
        <h1 className="app__title">ThreatWeave</h1>
        <p className="app__tagline">Deterministic threat-intelligence graph explorer</p>
      </header>
      <main className="app__main">
        <p className="app__placeholder">Graph explorer loading…</p>
      </main>
    </div>
  );
}
