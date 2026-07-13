"""Application configuration loaded from environment variables.

All settings come from the process environment (or a local ``.env`` file during
development). No secrets are hardcoded or committed; see ``.env.example`` for the
list of expected variable names.
"""

from __future__ import annotations

from functools import lru_cache

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
        """Return a libpq-style connection string."""
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.db}"
        )


class OTXSettings(BaseSettings):
    """Settings for the AlienVault OTX ingestion connector."""

    model_config = _section_config("OTX_")

    api_key: str = ""
    base_url: str = "https://otx.alienvault.com/api/v1"


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

    # Graph backend selection. "neo4j" (default) uses the running database;
    # "memory" uses the in-process store, handy for a no-Docker demo.
    graph_backend: str = Field(default="neo4j", alias="GRAPH_BACKEND")
    # When using the memory backend, optionally seed it from the local sample.
    seed_sample: bool = Field(default=False, alias="SEED_SAMPLE")

    # Vector backend for semantic similarity. "none" (default) disables it;
    # "pgvector" uses Postgres; "memory" is an in-process store for tests/demos.
    vector_backend: str = Field(default="none", alias="VECTOR_BACKEND")

    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    otx: OTXSettings = Field(default_factory=OTXSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance built from the environment."""
    return Settings()
