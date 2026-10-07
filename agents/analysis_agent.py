"""Grounded structured LLM analysis; transparent rule engine when offline."""

import json
from pydantic import ValidationError
from agents.base_agent import BaseAgent
from config import Config
from models import Analysis, Technique
from llm.provider import LLMProvider, ProviderError
from llm.prompts import SYSTEM_PROMPT, analysis_prompt
from intelligence import MITIGATIONS
from utils import cloud_event


class AnalysisAgent(BaseAgent):
    def __init__(self, config: Config, provider: LLMProvider) -> None:
        super().__init__("Analysis Agent")
        self.config, self.provider = config, provider

    def local_analysis(self, payload: dict) -> Analysis:
        event, h, docs = payload["event"], payload["hypothesis"], payload["documents"]
        source = next((d for d in docs if h["technique"] and h["technique"] in d["mitre_ids"]), None)
        mapping = (
            [
                Technique(
                    id=h["technique"],
                    name=h["technique_name"],
                    rationale=f"Candidate mapping for {h['name']}; validate with additional telemetry.",
                    source_id=source["source_id"],
                )
            ]
            if source
            else []
        )
        uncertainties = [
            "An anomaly alone does not prove malicious intent.",
            "No endpoint process tree, packet capture, or corroborating identity timeline was supplied.",
            "Attack chain stages are hypotheses requiring independent evidence.",
        ]
        if not docs:
            uncertainties.append("No relevant knowledge context was retrieved.")
        return Analysis(
            threat_name=h["name"],
            incident_summary=f"Possible {h['name'].lower()} on {event.get('host', 'unknown asset')} at {event['timestamp']}. "
            "Isolation Forest identified an unusual feature pattern; analyst validation is required.",
            threat_explanation=f"Telemetry is consistent with the {h['name'].lower()} triage hypothesis. "
            "Authorized administration, testing, or workload changes may produce similar observations.",
            attack_chain=[
                f"Observed: {event.get('message') or 'Unusual numeric telemetry'}",
                f"Hypothesis: {h['tactic']} activity; not independently confirmed.",
                "Next: correlate endpoint, identity, and network records to establish sequence.",
            ],
            mitre_mapping=mapping,
            severity=h["severity"],
            confidence=0.65 if h["key"] != "unknown" and docs else 0.4,
            risk_score=h["risk_score"],
            business_impact="Potential service disruption, account misuse, or data exposure. "
            "Actual impact and scope are unconfirmed; verify asset role and data classification.",
            technical_explanation=f"Model {event.get('model_id', 'unknown')} used eight numeric features with log1p scaling. "
            f"Anomaly score {event['anomaly_score']:.4f}; decision function {event.get('decision_function', 0):.4f}. "
            "The candidate threat derives from numerical thresholds and message indicators, not dataset labels.",
            recommended_mitigation=MITIGATIONS[h["key"]],
            citations=[source["source_id"]] if source else [d["source_id"] for d in docs[:2]],
            uncertainties=uncertainties,
        )

    @staticmethod
    def validate_grounding(analysis: Analysis, documents: list[dict]) -> None:
        sources = {d["source_id"]: d for d in documents}
        if any(c not in sources for c in analysis.citations):
            raise ValueError("LLM cited sources that were not retrieved.")
        for mapping in analysis.mitre_mapping:
            if mapping.source_id not in sources or mapping.id not in sources[mapping.source_id]["mitre_ids"]:
                raise ValueError("LLM produced an unsupported MITRE mapping.")
            if mapping.source_id not in analysis.citations:
                raise ValueError("MITRE mapping source is missing from citations.")
        if documents and not analysis.citations:
            raise ValueError("Analysis must cite retrieved evidence.")

    def run(self, payload: dict) -> dict:
        mode, reason = self.provider.name, ""
        cloud = mode in {"openai", "gemini"}
        if mode == "local":
            result = self.local_analysis(payload)
        elif cloud and not self.config.allow_cloud_logs:
            if not self.config.allow_fallback:
                raise ProviderError("Cloud log transmission requires ALLOW_CLOUD_LOGS=true.")
            result = self.local_analysis(payload)
            mode = "local"
            reason = "Cloud transmission is disabled; used local analysis."
        else:
            event = (
                cloud_event(payload["event"])
                if cloud
                else {
                    k: v for k, v in payload["event"].items() if k not in {"ground_truth", "attack_label", "event_type"}
                }
            )
            try:
                prompt = analysis_prompt(event, payload["documents"])
                if cloud:
                    from utils import redact_text

                    prompt = redact_text(prompt)
                raw = self.provider.complete(SYSTEM_PROMPT, prompt, True)
                if len(raw) > 50000:
                    raise ValueError("Provider output exceeds size bound.")
                result = Analysis.model_validate(json.loads(raw))
                self.validate_grounding(result, payload["documents"])
            except (ProviderError, ValueError, ValidationError, TypeError) as exc:
                if not self.config.allow_fallback:
                    raise ProviderError("Analysis failed validation or provider request.") from exc
                result = self.local_analysis(payload)
                mode = "local"
                reason = (
                    f"{self.provider.name} unavailable or output rejected ({type(exc).__name__}); used local analysis."
                )
                self.logger.warning(reason)
        return {
            **payload,
            "analysis": result.model_dump(),
            "analysis_provider": mode,
            "requested_provider": self.provider.name,
            "fallback_reason": reason,
        }
