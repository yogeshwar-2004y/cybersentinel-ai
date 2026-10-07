"""Final incident contract, provenance, and immutable investigation identity."""

from datetime import datetime, timezone
from agents.base_agent import BaseAgent
from utils import stable_id


class ReportAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("Report Agent")

    def run(self, payload: dict) -> dict:
        event = payload["event"]
        identity = {
            "event_id": event["event_id"],
            "model_id": event.get("model_id"),
            "knowledge": payload["kb_fingerprint"],
            "requested_provider": payload["requested_provider"],
            "actual_provider": payload["analysis_provider"],
            "pipeline_version": "1.0.0",
        }
        report = {
            "incident_id": stable_id(identity),
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "Open",
            "evidence": event,
            **payload["analysis"],
            **payload["response"],
            "provenance": {
                "analysis_provider": payload["analysis_provider"],
                "requested_provider": payload["requested_provider"],
                "fallback_reason": payload["fallback_reason"],
                "retrieval_mode": payload["retrieval_mode"],
                "kb_fingerprint": payload["kb_fingerprint"],
                "model_id": event.get("model_id"),
                "pipeline_version": "1.0.0",
                "confidence_definition": "Uncalibrated analyst heuristic; not a probability.",
                "risk_definition": "Heuristic prioritization on 0-100 scale; not measured business loss.",
            },
            "sources": payload["documents"],
            "agent_trace": list(payload.get("trace", [])),
        }
        return {**payload, "report": report}
