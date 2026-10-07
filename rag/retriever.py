"""Knowledge retrieval facade shared by agents, search, and grounded chat."""

from config import Config
from rag.embeddings import Embeddings
from rag.vector_store import VectorStore


class Retriever:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.embeddings = Embeddings(config)
        self.store = VectorStore(config, self.embeddings)

    def search(self, query: str, top_k: int | None = None) -> list[dict]:
        return self.store.search(query, top_k or self.config.top_k)

    @property
    def mode(self) -> str:
        return f"{self.embeddings.backend} / {self.store.backend}"
