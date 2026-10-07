"""Content-addressed FAISS indexes; JSON + NumPy persistence, never untrusted pickle."""

from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from threading import RLock
import numpy as np
from config import Config
from rag.embeddings import Embeddings


class VectorStore:
    def __init__(self, config: Config, embeddings: Embeddings) -> None:
        self.config, self.embeddings = config, embeddings
        self.documents: list[dict] = []
        self.index = None
        self.vectors = np.empty((0, 0), dtype="float32")
        self.backend = "numpy"
        self.fingerprint = ""
        self.lock = RLock()
        try:
            import faiss

            self.faiss = faiss
            self.backend = "faiss"
        except ImportError:
            self.faiss = None
        self.build()

    def build(self) -> None:
        """Rebuild automatically whenever the KB or embedding signature changes."""
        with self.lock:
            documents = []
            digest = hashlib.sha256(self.embeddings.signature.encode())
            for path in sorted(self.config.knowledge_dir.rglob("*.md")):
                content = path.read_text(encoding="utf-8")
                relative = path.relative_to(self.config.knowledge_dir).as_posix()
                digest.update(relative.encode())
                digest.update(content.encode())
                title = content.splitlines()[0].lstrip("# ").strip()
                ids = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", content)))
                # Paragraph windows retain section boundaries and source identities.
                paragraphs = content.split("\n\n")
                chunks, current = [], ""
                for paragraph in paragraphs:
                    if current and len(current) + len(paragraph) > 1800:
                        chunks.append(current)
                        current = ""
                    current += paragraph + "\n\n"
                if current.strip():
                    chunks.append(current)
                for i, chunk in enumerate(chunks):
                    documents.append(
                        {
                            "source_id": f"{relative}#chunk-{i}",
                            "title": title,
                            "path": relative,
                            "text": chunk.strip(),
                            "mitre_ids": ids,
                        }
                    )
            if not documents:
                raise ValueError("Knowledge base has no Markdown documents.")
            self.fingerprint = digest.hexdigest()
            folder = self.config.state_dir / "indexes" / self.fingerprint
            cache = folder / "vectors.npy"
            if cache.exists():
                try:
                    vectors = np.load(cache, allow_pickle=False)
                    if vectors.shape[0] != len(documents) or not np.isfinite(vectors).all():
                        raise ValueError("Invalid cached vectors")
                except (ValueError, OSError):
                    vectors = self.embeddings.encode([d["title"] + " " + d["text"] for d in documents])
            else:
                vectors = self.embeddings.encode([d["title"] + " " + d["text"] for d in documents])
            folder.mkdir(parents=True, exist_ok=True)
            # Atomic unique temporary writes allow multiple app processes to share the cache.
            from tempfile import NamedTemporaryFile

            with NamedTemporaryFile(dir=folder, suffix=".npy", delete=False) as tmp:
                np.save(tmp, vectors)
                tmp_path = Path(tmp.name)
            tmp_path.replace(cache)
            self.documents, self.vectors = documents, vectors
            if self.faiss is not None:
                self.index = self.faiss.IndexFlatIP(vectors.shape[1])
                self.index.add(vectors)
                # Search uses the in-memory index; persisted FAISS is a reproducible artifact.
                with NamedTemporaryFile(dir=folder, suffix=".faiss", delete=False) as tmp:
                    index_tmp = Path(tmp.name)
                self.faiss.write_index(self.index, str(index_tmp))
                index_tmp.replace(folder / "index.faiss")
            metadata = {
                "fingerprint": self.fingerprint,
                "embedding": self.embeddings.signature,
                "documents": documents,
                "backend": self.backend,
            }
            with NamedTemporaryFile(dir=folder, mode="w", encoding="utf-8", delete=False) as tmp:
                json.dump(metadata, tmp, indent=2)
                meta_tmp = Path(tmp.name)
            meta_tmp.replace(folder / "metadata.json")

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not query.strip():
            return []
        with self.lock:
            q = self.embeddings.encode([query[:4000]])
            k = max(1, min(top_k, len(self.documents)))
            if self.index is not None:
                scores, indices = self.index.search(q, k)
                pairs = zip(indices[0], scores[0])
            else:
                scores = self.vectors @ q[0]
                indices = np.argsort(-scores)[:k]
                pairs = ((i, scores[i]) for i in indices)
            return [{**self.documents[int(i)], "score": round(float(s), 5)} for i, s in pairs if i >= 0 and s > 0]
