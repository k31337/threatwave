"""Tests for PgVectorStore parameter binding, using a fake psycopg connection.

These do not talk to a real Postgres; they pin the contract that vector
parameters are wrapped in ``pgvector.Vector`` (plain lists would be sent as
``float8[]``, which the ``<=>`` operator rejects) and that LIMIT is clamped.
"""

from __future__ import annotations

from typing import Any

import pytest
from pgvector import Vector

import threatweave.vector.pgvector_store as pgv
from threatweave.vector.pgvector_store import PgVectorStore


class FakeCursor:
    """Records execute() calls; returns canned fetch results."""

    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> None:
        self._log.append((sql, params))

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list[Any]:
        return []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, Any]] = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.executed)

    def close(self) -> None:
        return None


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> tuple[PgVectorStore, FakeConnection]:
    conn = FakeConnection()
    monkeypatch.setattr(pgv.psycopg, "connect", lambda dsn, autocommit: conn)
    monkeypatch.setattr(pgv, "register_vector", lambda c: None)
    return PgVectorStore(dsn="postgresql://x", dim=3), conn


def test_schema_created_with_dimension(store: tuple[PgVectorStore, FakeConnection]) -> None:
    _, conn = store
    statements = [sql for sql, _ in conn.executed]
    assert any("CREATE EXTENSION IF NOT EXISTS vector" in sql for sql in statements)
    assert any("vector(3)" in sql for sql in statements)


def test_upsert_binds_vector_type(store: tuple[PgVectorStore, FakeConnection]) -> None:
    pg_store, conn = store
    pg_store.upsert("e1", [1.0, 2.0, 3.0], content_hash="h")

    _, params = conn.executed[-1]
    assert params[0] == "e1"
    assert params[1] == "h"
    # Regression: must be a pgvector.Vector, not a plain list (float8[]).
    assert isinstance(params[2], Vector)


def test_search_binds_vector_type_and_clamps_limit(
    store: tuple[PgVectorStore, FakeConnection],
) -> None:
    pg_store, conn = store
    pg_store.search([1.0, 0.0, 0.0], k=-5, exclude="me")

    sql, params = conn.executed[-1]
    assert "LIMIT %s" in sql
    # Both vector occurrences wrapped; exclude passed; negative k clamped to 0.
    assert isinstance(params[0], Vector)
    assert params[1] == "me"
    assert isinstance(params[2], Vector)
    assert params[3] == 0
