"""Retrieval relevance, invalidation, persistence, and offline fallback tests."""

from dataclasses import replace
import json
import numpy as np
import pytest
from rag.retriever import Retriever
from rag.embeddings import Embeddings


def test_retrieves_brute_force_with_citation(workflow):
    docs = workflow.retriever.search("brute force password guessing T1110", 3)
    assert docs and any("T1110" in d["mitre_ids"] for d in docs)
    assert all("source_id" in d and d["score"] > 0 for d in docs)


def test_empty_query(workflow):
    assert workflow.retriever.search("   ") == []


def test_normalized_embeddings(config):
    emb = Embeddings(config)
    matrix = emb.encode(["brute force authentication", "DNS tunneling"])
    np.testing.assert_allclose(np.linalg.norm(matrix, axis=1), 1, atol=1e-6)


def test_corpus_changes_rebuild_index(config, tmp_path):
    kb = tmp_path / "kb"
    kb.mkdir()
    path = kb / "test.md"
    path.write_text("# Example\n\nBrute force T1110 authentication.", encoding="utf-8")
    config = replace(config, knowledge_dir=kb)
    first = Retriever(config)
    before = first.store.fingerprint
    path.write_text("# Example\n\nDNS tunneling T1071.004 resolver.", encoding="utf-8")
    second = Retriever(config)
    assert second.store.fingerprint != before
    assert second.search("DNS tunneling")[0]["mitre_ids"] == ["T1071.004"]


def test_index_persisted(workflow, config):
    folder = config.state_dir / "indexes" / workflow.retriever.store.fingerprint
    assert (folder / "vectors.npy").exists()
    assert json.loads((folder / "metadata.json").read_text())["documents"]
    if workflow.retriever.store.backend == "faiss":
        assert (folder / "index.faiss").exists()


def test_numpy_search_fallback(config, monkeypatch):
    import builtins

    original = builtins.__import__

    def controlled(name, *args, **kwargs):
        if name == "faiss":
            raise ImportError("unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", controlled)
    r = Retriever(config)
    assert r.store.backend == "numpy"
    assert r.search("brute force")[0]["title"] == "Brute Force"


def test_auto_embedding_fallback(config, monkeypatch):
    import builtins

    original = builtins.__import__

    def controlled(name, *args, **kwargs):
        if name == "sentence_transformers":
            raise ImportError("unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", controlled)
    emb = Embeddings(replace(config, embedding_backend="auto"))
    assert emb.backend == "hashing" and emb.fallback_reason


def test_empty_kb_rejected(config, tmp_path):
    folder = tmp_path / "empty"
    folder.mkdir()
    with pytest.raises(ValueError):
        Retriever(replace(config, knowledge_dir=folder))
