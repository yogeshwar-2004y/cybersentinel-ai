"""Typed, bounded contracts shared by all agents and report exports."""

from typing import Literal
from pydantic import BaseModel, Field, ConfigDict


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Technique(Contract):
    id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=1, max_length=1000)
    source_id: str = Field(min_length=1, max_length=200)


class Analysis(Contract):
    threat_name: str = Field(min_length=1, max_length=200)
    incident_summary: str = Field(min_length=1, max_length=3000)
    threat_explanation: str = Field(min_length=1, max_length=4000)
    attack_chain: list[str] = Field(min_length=1, max_length=12)
    mitre_mapping: list[Technique] = Field(default_factory=list, max_length=12)
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    business_impact: str = Field(min_length=1, max_length=3000)
    technical_explanation: str = Field(min_length=1, max_length=4000)
    recommended_mitigation: list[str] = Field(min_length=1, max_length=15)
    citations: list[str] = Field(default_factory=list, max_length=15)
    uncertainties: list[str] = Field(min_length=1, max_length=12)


class PlaybookStep(Contract):
    phase: str
    action: str
    owner: str
    approval_required: bool = True
    validation: str


class ResponsePlan(Contract):
    recommended_actions: list[str]
    playbook: list[PlaybookStep]
    soc_checklist: list[str]
    next_investigation_steps: list[str]
    recovery: list[str]
