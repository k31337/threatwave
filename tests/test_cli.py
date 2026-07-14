"""Tests for the CLI: argument parsing and the ingest-doc command (mocked LLM)."""

from __future__ import annotations

import argparse
import os

import pytest

from tests.conftest import FakeProvider
from threatweave.cli import build_parser, run_demo, run_ingest_doc
from threatweave.graph.memory import InMemoryGraphStore


def test_parser_requires_a_source() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["ingest-doc"])


def test_parser_rejects_multiple_sources() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["ingest-doc", "--url", "u", "--text", "t"])


def test_run_ingest_doc_from_text_populates_graph(
    store: InMemoryGraphStore, fake_provider: FakeProvider
) -> None:
    args = argparse.Namespace(
        url=None, file=None, text="APT-Sample phishing 198.51.100.23 evil.example"
    )
    run_ingest_doc(args, store=store, provider=fake_provider)

    assert store.get_node("actor:APT-Sample") is not None
    assert store.get_node("ttp:T1566.001") is not None
    assert store.get_node("ioc:ipv4:198.51.100.23") is not None


def test_run_ingest_doc_from_file(
    tmp_path, store: InMemoryGraphStore, fake_provider: FakeProvider
) -> None:
    report = tmp_path / "report.txt"
    report.write_text("APT-Sample C2 at 8.8.8.8", encoding="utf-8")

    args = argparse.Namespace(url=None, file=str(report), text=None)
    run_ingest_doc(args, store=store, provider=fake_provider)

    assert store.get_node("ioc:ipv4:8.8.8.8") is not None
    assert store.get_node("actor:APT-Sample") is not None


def test_parser_wires_demo_defaults() -> None:
    args = build_parser().parse_args(["demo"])
    assert args.func is run_demo
    assert args.host == "127.0.0.1"
    assert args.port == 8000
    assert args.reload is False


def test_run_demo_forces_memory_backend_and_serves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GRAPH_BACKEND", raising=False)
    monkeypatch.delenv("SEED_SAMPLE", raising=False)
    captured: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        # Env must already be set to the seeded in-memory backend at serve time.
        captured["app"] = app
        captured["graph_backend"] = os.environ["GRAPH_BACKEND"]
        captured["seed_sample"] = os.environ["SEED_SAMPLE"]
        captured["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", fake_run)

    args = argparse.Namespace(host="127.0.0.1", port=9001, reload=False)
    run_demo(args)

    assert captured["app"] == "threatweave.api.app:app"
    assert captured["graph_backend"] == "memory"
    assert captured["seed_sample"] == "true"
    assert captured["kwargs"] == {"host": "127.0.0.1", "port": 9001, "reload": False}
