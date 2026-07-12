"""Application configuration loaded from environment variables.

All settings come from the process environment (or a local ``.env`` file during
development). No secrets are hardcoded or committed; see ``.env.example`` for the
list of expected variable names.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Neo4jSettings(BaseSettings):
    """Connection settings for the Neo4j graph store."""

    model_config = SettingsConfigDict(env_prefix="NEO4J_")

    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = ""


class PostgresSettings(BaseSettings):
    """Connection settings for PostgreSQL + pgvector.

    Reserved for the embeddings phase; the graph flow does not use it yet.
    """

    model_config = SettingsConfigDict(env_prefix="POSTGRES_")

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

    model_config = SettingsConfigDict(env_prefix="OTX_")

    api_key: str = ""
    base_url: str = "https://otx.alienvault.com/api/v1"


class LLMSettings(BaseSettings):
    """Settings for the pluggable LLM provider.

    Reserved: no provider is wired in until the AI enrichment phase. ``provider``
    defaults to ``"none"`` so nothing attempts to call an external model.
    """

    model_config = SettingsConfigDict(env_prefix="LLM_")

    provider: str = "none"
    api_key: str = ""
    model: str = ""


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

    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    otx: OTXSettings = Field(default_factory=OTXSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance built from the environment."""
    return Settings()
