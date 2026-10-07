"""Retrieve local guidance relevant to anomaly evidence and triage hypothesis."""

from agents.base_agent import BaseAgent
from rag.retriever import Retriever


class ThreatIntelligenceAgent(BaseAgent):
    def __init__(self, retriever: Retriever) -> None:
        super().__init__("Threat Intelligence Agent")
        self.retriever = retriever

    def run(self, payload: dict) -> dict:
        event, candidate = payload["event"], payload["hypothesis"]
        query = f"{candidate['name']} {candidate['technique'] or ''} indicators detection mitigation "
        query += str(event.get("message", ""))[:1000]
        documents = self.retriever.search(query)
        return {
            **payload,
            "documents": documents,
            "retrieval_query": query,
            "retrieval_mode": self.retriever.mode,
            "kb_fingerprint": self.retriever.store.fingerprint,
        }
