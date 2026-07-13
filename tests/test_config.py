"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatweave.config import Settings

# Env vars touched by these tests; cleared so a developer's exported values
# cannot make the assertions flaky.
_VARS = (
    "GRAPH_BACKEND",
    "VECTOR_BACKEND",
    "NEO4J_PASSWORD",
    "LLM_PROVIDER",
    "LLM_NARRATIVE_MODEL",
    "OTX_API_KEY",
    "POSTGRES_HOST",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def test_nested_sections_read_dotenv_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: values in .env (not exported) must reach nested sections.

    Sections are standalone BaseSettings built via default_factory, so they do
    not inherit the parent's env_file — each must read .env itself.
    """
    (tmp_path / ".env").write_text(
        "GRAPH_BACKEND=memory\n"
        "NEO4J_PASSWORD=dotenv-secret\n"
        "LLM_PROVIDER=openai\n"
        "OTX_API_KEY=dotenv-otx-key\n"
        "POSTGRES_HOST=dotenv-host\n",
        encoding="utf-8",
    )
    # env_file is resolved relative to the working directory.
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.graph_backend == "memory"  # top-level alias
    assert settings.neo4j.password == "dotenv-secret"
    assert settings.llm.provider == "openai"
    assert settings.otx.api_key == "dotenv-otx-key"
    assert settings.postgres.host == "dotenv-host"


def test_environment_overrides_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Process environment variables take precedence over the .env file."""
    (tmp_path / ".env").write_text("NEO4J_PASSWORD=from-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NEO4J_PASSWORD", "from-env")

    assert Settings().neo4j.password == "from-env"


def test_defaults_without_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a .env file everything falls back to defaults."""
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.graph_backend == "neo4j"
    assert settings.vector_backend == "none"
    assert settings.llm.provider == "none"
    assert settings.llm.narrative_model == "gpt-5.4-mini"
