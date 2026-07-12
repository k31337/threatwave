# ThreatWeave

A threat intelligence knowledge graph. ThreatWeave ingests IOCs (IPs, hashes,
domains, URLs) and cybersecurity reports from multiple sources, normalizes them,
and correlates them in a knowledge graph. Its differentiator over a plain feed
aggregator is finding relationships that exact matching misses — via semantic
similarity with embeddings (a later phase).

## Architecture principle

Structural correlation is **deterministic**: a graph, a JOIN, an edge traversal.
AI is reserved for exactly three ingestion-time jobs:

1. extracting IOCs/TTPs from free text,
2. generating embeddings,
3. writing explanatory narratives on demand.

An LLM is **never** used to correlate IOCs or decide structural relationships —
that is graph logic, and putting AI there would add cost and hallucinations to
data that must be exact. All AI access goes through a single, swappable
`LLMProvider` interface (`extract` / `embed` / `narrate`).

**Hybrid extraction.** Obvious IOCs (IPs, domains, hashes, URLs) are pulled by
the deterministic regex parser at zero token cost. The LLM is used *only* for
what regex cannot recover — TTPs (mapped to MITRE ATT&CK), the attributed actor
and targeted sectors — so the two never duplicate work.

**Semantic similarity is additive.** Embeddings (computed once per campaign at
ingestion, cached in pgvector) let the graph relate campaigns that read alike but
share no exact IOC. This *augments* the exact-match structural correlation with
scored `semantic_similarity` edges — it never replaces it, and the AI still only
touches each datum once, at ingestion.

## Stack

- Python 3.11+, FastAPI
- Neo4j (graph), PostgreSQL + pgvector (embeddings)
- Docker Compose for local infrastructure
- Deterministic IOC extraction via regex/parsers (no AI)
- pytest, ruff, full type hints

## Project layout

```
src/threatweave/
├── config.py            # pydantic-settings, loaded from .env
├── models/              # domain models (IOC, Actor, Campaign, TTP, graph value objects) + normalization
├── parsers/             # deterministic regex IOC parser (+ refanging)
├── connectors/          # ingestion sources: AlienVault OTX + free-text/URL documents
├── graph/               # GraphStore port + Neo4j and in-memory adapters + factory
├── vector/              # VectorStore port + pgvector and in-memory adapters + factory
├── correlation/         # correlate() (structural + semantic) and similar()
├── ingest.py            # OTX payload / extracted document -> graph (+ cached embeddings)
├── llm/                 # LLMProvider interface + OpenAI provider, Ollama stub, cost, factory
├── cli.py               # `threatweave` CLI (ingest-doc)
└── api/                 # FastAPI app and routes
```

The graph models five node kinds — `IOC`, `Actor`, `Campaign`, `TTP`, `Sector` —
linked by deterministic relationships (`PART_OF`, `ATTRIBUTED_TO`, `RESOLVES_TO`,
`USES`, `TARGETS`), plus a weighted `SEMANTIC_SIMILARITY` edge (carrying a cosine
score) added at query time from campaign embeddings.

## Configuration

All configuration comes from environment variables. Copy the template and fill
in values (never commit `.env`):

```bash
cp .env.example .env
```

Key variables: `NEO4J_*`, `POSTGRES_*`, `OTX_API_KEY`, `API_*`,
`GRAPH_BACKEND` (`neo4j` | `memory`) and `SEED_SAMPLE`. For document ingestion,
set the LLM provider: `LLM_PROVIDER=openai`, `LLM_API_KEY=<key>`,
`LLM_MODEL=gpt-4o-mini` (plus optional `LLM_MAX_INPUT_CHARS`,
`LLM_MAX_OUTPUT_TOKENS`, `LLM_MAX_RETRIES`). For semantic similarity, enable a
vector backend: `VECTOR_BACKEND=pgvector` (or `memory`), with
`LLM_EMBED_MODEL=text-embedding-3-small` and `LLM_EMBED_DIM=1536`. See
[.env.example](.env.example) for the full list.

## Install (development)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

## Running

### Option A — no Docker, in-memory demo (fastest)

Runs the API against the in-process graph, seeded from the synthetic sample in
`data/samples/`:

```bash
GRAPH_BACKEND=memory SEED_SAMPLE=true uvicorn threatweave.api.app:app --reload
```

Then query a correlation subgraph:

```bash
curl "http://localhost:8000/api/correlate?ioc=malicious.example&depth=2"
```

You should get a JSON subgraph containing the queried indicator, its sibling
IOCs from the same OTX pulse, and the `Synthetic APT-Test Infrastructure`
campaign node, plus the edges linking them.

### Option B — full stack with Docker (Neo4j + Postgres + API)

```bash
docker compose up --build
```

This starts Neo4j (browser UI at http://localhost:7474, Bolt on 7687), a
pgvector-enabled Postgres (reserved for the embeddings phase), and the API on
`http://localhost:8000`. Populate the graph from OTX by running an ingest against
the running Neo4j (requires a valid `OTX_API_KEY`).

## API

| Method | Path              | Description                                            |
|--------|-------------------|--------------------------------------------------------|
| GET    | `/health`         | Liveness probe.                                        |
| GET    | `/api/correlate`  | Correlation subgraph for an indicator.                 |
| GET    | `/api/similar`    | Semantic nearest neighbours of an entity.              |

`GET /api/correlate?ioc=<value>&depth=<1..4>` — the indicator type is inferred
from the value (IP, domain, hash or URL). Returns `404` if the indicator is not
in the graph. The response is a `{ "nodes": [...], "edges": [...] }` subgraph.
Add `&semantic=true` (with a vector backend configured) to also include scored
`semantic_similarity` edges (tunable via `&k=` and `&min_score=`).

`GET /api/similar?id=<entity_id>&k=<n>` — returns the `k` most semantically
similar entities as `[{ "id", "label", "score" }]`, e.g.
`id=campaign:<name>`. Responds `503` if no vector backend is configured, or
`404` if the entity has no stored embedding.

## Ingesting documents (CLI)

`threatweave ingest-doc` ingests an unstructured threat report — a blog post,
CERT advisory or social-media post — from a URL, a file or inline text. It runs
hybrid extraction (regex IOCs + LLM TTPs/actor/sectors) and writes the result to
the graph, building the `Campaign`, `Actor`, `TTP` and `Sector` nodes and their
edges. Requires an LLM provider configured (`LLM_PROVIDER=openai`, `LLM_API_KEY`).

```bash
threatweave ingest-doc --url https://example.com/threat-report
threatweave ingest-doc --file data/samples/threat_report.txt
threatweave ingest-doc --text "APT-Sample phishing campaign targeting finance ..."
```

Each call prints a summary (campaign id, IOC/TTP counts, actor, sectors, and the
estimated token cost is logged). Afterwards the extracted entities are queryable
through `/api/correlate`.

## Testing

The full suite runs offline — no Neo4j, pgvector, Docker, network or API keys
required. Correlation and similarity run against in-memory stores, the OTX
connector against a mocked transport, and the LLM provider is fully mocked (fixed
extractions and deterministic embeddings), so extraction, embeddings and document
ingestion are tested without any real API calls:

```bash
pytest          # run tests
ruff check .    # lint
```

## Data & security

- No secrets in the repo — everything via environment variables.
- `.env` is git-ignored; only `.env.example` (names, no values) is committed.
- Real intelligence data stays out of the repo; `data/samples/` holds only
  synthetic or public data.

## Roadmap

- [x] **Phase 1 — Base graph**: project skeleton, deterministic IOC parsing,
  AlienVault OTX ingestion, Neo4j graph model with an in-memory test backend,
  deterministic correlation and a FastAPI query endpoint. No AI. The `LLMProvider`
  interface and the pgvector infrastructure are defined but not yet implemented.
- [x] **Phase 2 — LLM extraction**: hybrid document ingestion (`threatweave
  ingest-doc`) — regex IOCs plus LLM-extracted TTPs (MITRE ATT&CK), actor and
  target sectors via a swappable `OpenAIProvider` (Ollama stub reserved), with
  token-cost logging and structured-output validation. Extraction inserts
  `Campaign`/`Actor`/`TTP`/`Sector` nodes and their edges.
- [x] **Phase 3 — Semantic similarity**: per-campaign embeddings (`embed`),
  computed once at ingestion and cached in a `VectorStore` (pgvector, with an
  in-memory test backend). Adds `similar(entity, k)`, scored
  `semantic_similarity` edges in `correlate()`, and a `GET /api/similar`
  endpoint — relating campaigns that share no exact IOC.
- [ ] Phase 4 — On-demand explanatory narratives (`narrate`).
