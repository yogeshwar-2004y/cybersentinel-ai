"""Explicit agent boundaries and execution telemetry."""

from abc import ABC, abstractmethod
from typing import Any
import logging
import time


class BaseAgent(ABC):
    def __init__(self, name: str) -> None:
        self.name = name
        self.logger = logging.getLogger(f"agents.{name}")

    @abstractmethod
    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Transform a validated workflow payload."""

    def execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            result = self.run(payload)
        except Exception:
            self.logger.error("Agent failed: %s", self.name)
            raise
        trace = list(payload.get("trace", []))
        trace.append(
            {"agent": self.name, "duration_ms": round((time.perf_counter() - start) * 1000, 2), "status": "completed"}
        )
        result["trace"] = trace
        return result
