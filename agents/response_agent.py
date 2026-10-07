"""Construct reviewable defensive playbooks without executing response actions."""

from agents.base_agent import BaseAgent
from models import ResponsePlan, PlaybookStep


class ResponseAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__("Response Agent")

    def run(self, payload: dict) -> dict:
        analysis = payload["analysis"]
        actions = analysis["recommended_mitigation"]
        steps = [
            PlaybookStep(
                phase="Triage",
                action="Confirm anomaly, asset owner, scope, and change window.",
                owner="SOC analyst",
                approval_required=False,
                validation="Document whether activity was authorized and record corroborating sources.",
            ),
            PlaybookStep(
                phase="Preserve",
                action="Collect relevant logs and forensic artifacts with hashes and timestamps.",
                owner="Incident responder",
                approval_required=False,
                validation="Evidence manifest and chain of custody are complete.",
            ),
            PlaybookStep(
                phase="Contain",
                action=actions[0] + " Approve any account, host, or network restriction before execution.",
                owner="Incident commander",
                validation="Containment scope is approved and business impact assessed.",
            ),
            PlaybookStep(
                phase="Eradicate",
                action=actions[-1],
                owner="Platform owner",
                validation="Root cause has been addressed and telemetry reviewed.",
            ),
            PlaybookStep(
                phase="Recover",
                action="Restore validated services, check integrity, and monitor for recurrence.",
                owner="Service owner",
                validation="Service tests pass and recovery is approved.",
            ),
            PlaybookStep(
                phase="Learn",
                action="Record lessons, update detection logic, and review response timing.",
                owner="SOC lead",
                approval_required=False,
                validation="Review is recorded with accountable owners.",
            ),
        ]
        plan = ResponsePlan(
            recommended_actions=actions,
            playbook=steps,
            soc_checklist=[
                "Validate event time and collection source.",
                "Confirm business authorization.",
                "Preserve raw logs and evidence hashes.",
                "Assess asset criticality and affected identities.",
                "Document containment approval.",
                "Assign investigation owner and escalation deadline.",
            ],
            next_investigation_steps=[
                "Search surrounding 30 minutes for the same host, user, and source.",
                "Correlate endpoint process ancestry and identity session records.",
                "Check related hosts and destinations against authorized workflows.",
                "Confirm candidate MITRE mapping with independent evidence.",
            ],
            recovery=[
                "Verify clean backups and known-good configurations.",
                "Restore in stages with the service owner; monitor health and indicators.",
                "Rotate exposed credentials after approved containment when exposure is established.",
            ],
        )
        return {**payload, "response": plan.model_dump()}
