"""Sentence Transformer embeddings with a deterministic no-download fallback."""

from __future__ import annotations
import logging
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from config import Config

log = logging.getLogger(__name__)


class Embeddings:
    def __init__(self, config: Config) -> None:
        self.model = None
        self.backend = "hashing"
        self.fallback_reason = ""
        if config.embedding_backend != "hashing":
            try:
                from sentence_transformers import SentenceTransformer

                self.model = SentenceTransformer(
                    config.embedding_model,
                    device="cpu",
                    local_files_only=not config.allow_model_download,
                    trust_remote_code=False,
                )
                self.backend = "sentence_transformer"
            except Exception as exc:
                if config.embedding_backend == "sentence_transformer":
                    raise RuntimeError("Cannot load embedding model. Cache it or enable ALLOW_MODEL_DOWNLOAD.") from exc
                self.fallback_reason = (
                    f"Sentence Transformer unavailable ({type(exc).__name__}); lexical hashing active."
                )
                log.warning(self.fallback_reason)
        self.signature = f"st:{config.embedding_model}:normalized:v1" if self.model else "hashing:2048:word12:v1"
        self.vectorizer = HashingVectorizer(
            n_features=2048, alternate_sign=False, norm="l2", ngram_range=(1, 2), lowercase=True
        )

    def encode(self, texts: list[str]) -> np.ndarray:
        if self.model is not None:
            values = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        else:
            values = self.vectorizer.transform(texts).toarray()
        return np.ascontiguousarray(values, dtype="float32")
