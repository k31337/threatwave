"""Application configuration loaded from environment variables.

All settings come from the process environment (or a local ``.env`` file during
development). No secrets are hardcoded or committed; see ``.env.example`` for the
list of expected variable names.
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import quote

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _section_config(env_prefix: str) -> SettingsConfigDict:
    """Shared config for per-subsystem settings sections.

    Each section reads the ``.env`` file itself (not only the process
    environment): sections are standalone ``BaseSettings`` built via
    ``default_factory``, so they do NOT inherit the parent's ``env_file`` —
    without this, values placed in ``.env`` but not exported would be silently
    ignored. ``extra="ignore"`` skips the file's unrelated keys.
    """
    return SettingsConfigDict(
        env_prefix=env_prefix,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class Neo4jSettings(BaseSettings):
    """Connection settings for the Neo4j graph store."""

    model_config = _section_config("NEO4J_")

    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = ""


class PostgresSettings(BaseSettings):
    """Connection settings for PostgreSQL + pgvector.

    Reserved for the embeddings phase; the graph flow does not use it yet.
    """

    model_config = _section_config("POSTGRES_")

    host: str = "localhost"
    port: int = 5432
    db: str = "threatweave"
    user: str = "threatweave"
    password: str = ""

    @property
    def dsn(self) -> str:
        """Return a libpq-style connection string.

        User, password and database name are URL-escaped: characters like
        ``@ / :`` in a password would otherwise make the URI parse silently
        wrong (splitting at the wrong ``@``), not just fail.
        """
        user = quote(self.user, safe="")
        password = quote(self.password, safe="")
        db = quote(self.db, safe="")
        return f"postgresql://{user}:{password}@{self.host}:{self.port}/{db}"


class OTXSettings(BaseSettings):
    """Settings for the AlienVault OTX ingestion connector."""

    model_config = _section_config("OTX_")

    api_key: str = ""
    base_url: str = "https://otx.alienvault.com/api/v1"

    # Include OTX when running `threatweave ingest --all`.
    enabled: bool = False
    # Opt-in embedding of pulse descriptions for semantic search. Off by default
    # so scheduled OTX ingestion makes zero AI calls (the cost rule); on, it
    # preserves semantic similarity over feed descriptions — the project's edge.
    embed_descriptions: bool = False


class AbuseChSettings(BaseSettings):
    """Settings for the abuse.ch ingestion connectors.

    abuse.ch gates its feeds behind a single account ``Auth-Key``, shared across
    URLhaus and MalwareBazaar; Feodo Tracker's blocklist is public. Base URLs are
    overridable so the connectors can be pointed at a mock in tests.
    """

    model_config = _section_config("ABUSECH_")

    auth_key: str = ""
    urlhaus_base_url: str = "https://urlhaus.abuse.ch"
    malwarebazaar_base_url: str = "https://mb-api.abuse.ch/api/v1"
    feodo_base_url: str = "https://feodotracker.abuse.ch"

    # Include the abuse.ch feeds when running `threatweave ingest --all`.
    enabled: bool = False


class LLMSettings(BaseSettings):
    """Settings for the pluggable LLM provider.

    Reserved: no provider is wired in until the AI enrichment phase. ``provider``
    defaults to ``"none"`` so nothing attempts to call an external model.
    """

    model_config = _section_config("LLM_")

    provider: str = "none"
    api_key: str = ""
    model: str = ""

    # Cost / safety controls for extraction calls.
    max_input_chars: int = 48_000  # ~12k tokens; longer input is truncated.
    max_output_tokens: int = 1_024
    max_retries: int = 2  # transient-error retries handled by the SDK client.

    # Embeddings (semantic similarity phase).
    embed_model: str = "text-embedding-3-small"
    embed_dim: int = 1_536

    # On-demand narrative generation uses a higher-quality model than extraction.
    # Configurable so quality/cost can be tuned without code changes.
    narrative_model: str = "gpt-5.4-mini"


class Settings(BaseSettings):
    """Top-level application settings, aggregating each subsystem's config."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")

    # Casual API-key gating for the public API. NOT a strong secret: the SPA
    # ships it in its bundle (VITE_API_KEY), so treat it as drive-by gating, not
    # real authentication. Empty (the default, and the in-memory demo) disables
    # the check so the demo runs without keys. Real protection is the rate limit.
    api_key: str = Field(default="", alias="API_KEY")
    # Per-client rate limit for the /api/* routes, in slowapi syntax.
    api_rate_limit: str = Field(default="60/minute", alias="API_RATE_LIMIT")

    # Graph backend selection. "neo4j" (default) uses the running database;
    # "memory" uses the in-process store, handy for a no-Docker demo.
    graph_backend: str = Field(default="neo4j", alias="GRAPH_BACKEND")
    # When using the memory backend, optionally seed it from the local sample.
    seed_sample: bool = Field(default=False, alias="SEED_SAMPLE")

    # Vector backend for semantic similarity. "none" (default) disables it;
    # "pgvector" uses Postgres; "memory" is an in-process store for tests/demos.
    vector_backend: str = Field(default="none", alias="VECTOR_BACKEND")

    # Scheduled ingestion (`threatweave ingest`). The state file records the last
    # run per source (also read by GET /api/ingest/status); the interval is the
    # recommended cadence for a cron/Task Scheduler job (and the in-process
    # scheduler, if used). The CLI itself runs once and exits — cron drives it.
    ingest_state_path: str = Field(default="data/ingest_state.json", alias="INGEST_STATE_PATH")
    ingest_interval_minutes: int = Field(default=60, alias="INGEST_INTERVAL_MINUTES")

    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    otx: OTXSettings = Field(default_factory=OTXSettings)
    abusech: AbuseChSettings = Field(default_factory=AbuseChSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance built from the environment."""
    return Settings()
