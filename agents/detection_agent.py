"""Validate ML anomaly evidence before forwarding to intelligence."""

import math
from agents.base_agent import BaseAgent
from config import FEATURES
from intelligence import hypothesis


class DetectionAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("Detection Agent")

    def run(self, payload: dict) -> dict:
        event = dict(payload["event"])
        if int(event.get("prediction", 1)) != -1:
            raise ValueError("Detection Agent accepts only scored anomalies.")
        for key in (*FEATURES, "anomaly_score", "confidence"):
            value = float(event[key])
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid anomaly evidence: {key}")
        if not 0 <= float(event["confidence"]) <= 1:
            raise ValueError("Confidence must be bounded.")
        h = hypothesis(event)
        observations = [f"{key}={event[key]:g}" for key in FEATURES]
        return {
            **payload,
            "event": event,
            "hypothesis": h,
            "detection": {
                "validated": True,
                "observations": observations,
                "caveat": "Statistical outlier; a security incident is not yet confirmed.",
            },
        }
