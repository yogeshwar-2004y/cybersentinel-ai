"""Bounded orchestration: detection -> intelligence -> analysis -> response -> report."""

from config import Config
from agents.detection_agent import DetectionAgent
from agents.threat_agent import ThreatIntelligenceAgent
from agents.analysis_agent import AnalysisAgent
from agents.response_agent import ResponseAgent
from agents.report_agent import ReportAgent
from history import IncidentHistory
from llm.provider import create_provider, ProviderError
from llm.prompts import CHAT_SYSTEM, chat_prompt
from rag.retriever import Retriever


class SOCWorkflow:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.retriever = Retriever(config)
        self.provider = create_provider(config)
        self.history = IncidentHistory(config.state_dir / "incidents.db")
        self.agents = [
            DetectionAgent(),
            ThreatIntelligenceAgent(self.retriever),
            AnalysisAgent(config, self.provider),
            ResponseAgent(),
            ReportAgent(),
        ]

    def investigate(self, event: dict) -> dict:
        payload = {"event": event, "trace": []}
        for agent in self.agents:
            payload = agent.execute(payload)
        report = payload["report"]
        report["agent_trace"] = payload["trace"]
        return self.history.save(report)

    def chat(self, question: str, history: list[dict] | None = None) -> dict:
        if not question.strip() or len(question) > 2000:
            raise ValueError("Question must be 1-2000 characters.")
        documents = self.retriever.search(question)
        cloud = self.provider.name in {"openai", "gemini"}
        mode, reason = self.provider.name, ""
        if mode != "local" and (not cloud or self.config.allow_cloud_logs):
            try:
                answer = self.provider.complete(CHAT_SYSTEM, chat_prompt(question, documents, history or [], cloud))
                if len(answer) > 30000:
                    raise ProviderError("Chat output exceeds size bound.")
                return {"answer": answer, "sources": documents, "provider": mode, "fallback_reason": reason}
            except ProviderError as exc:
                if not self.config.allow_fallback:
                    raise
                reason = f"Provider failed ({type(exc).__name__}); local knowledge excerpts returned."
        elif mode != "local":
            if not self.config.allow_fallback:
                raise ProviderError("Cloud transmission requires explicit opt-in.")
            reason = "Cloud transmission disabled; local knowledge excerpts returned."
        if documents:
            answer = "Local knowledge excerpts (deterministic retrieval, no generative model):\n\n"
            answer += "\n\n".join(f"**{d['title']}** [{d['source_id']}]\n{d['text']}" for d in documents[:3])
        else:
            answer = "No relevant knowledge was found. Add appropriate source documents before drawing a conclusion."
        return {"answer": answer, "sources": documents, "provider": "local", "fallback_reason": reason}
