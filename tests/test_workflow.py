"""Agent boundaries, grounded explanations, history consistency, and local chat."""

import pytest
from agents.detection_agent import DetectionAgent
from agents.analysis_agent import AnalysisAgent
from models import Analysis
from intelligence import hypothesis
from utils import cloud_event


def test_full_workflow(report):
    assert report["incident_id"].startswith("INC-")
    assert len(report["agent_trace"]) == 5
    assert report["mitre_mapping"][0]["id"] == "T1110"
    assert report["sources"] and report["recommended_actions"] and len(report["playbook"]) == 6
    AnalysisAgent.validate_grounding(
        Analysis.model_validate({k: report[k] for k in Analysis.model_fields}), report["sources"]
    )


def test_normal_event_rejected(anomaly):
    anomaly["prediction"] = 1
    with pytest.raises(ValueError):
        DetectionAgent().execute({"event": anomaly})


def test_detection_labels_ignored(anomaly):
    original = hypothesis(anomaly)
    anomaly["ground_truth"] = "normal"
    anomaly["event_type"] = "Ransomware"
    assert hypothesis(anomaly) == original


def test_history_dedup_preserves_status(workflow, anomaly):
    first = workflow.investigate(anomaly)
    workflow.history.update_status(first["incident_id"], "Investigating", "Assigned to duty analyst", first["revision"])
    second = workflow.investigate(anomaly)
    assert first["incident_id"] == second["incident_id"]
    assert second["status"] == "Investigating" and len(workflow.history.list()) == 1
    assert len(workflow.history.audit(first["incident_id"])) == 1


def test_revision_guard(workflow, report):
    workflow.history.update_status(
        report["incident_id"], "Contained", "Approved scoped containment", report["revision"]
    )
    with pytest.raises(ValueError, match="another session"):
        workflow.history.update_status(report["incident_id"], "Resolved", "Complete", report["revision"])


def test_audit_note_required(workflow, report):
    with pytest.raises(ValueError):
        workflow.history.update_status(report["incident_id"], "Resolved", "", report["revision"])


def test_local_chat_has_sources(workflow):
    result = workflow.chat("How do I mitigate brute force attempts?")
    assert result["sources"] and "source" not in result["answer"].lower()[:10]
    assert result["provider"] == "local" and "brute_force.md" in result["answer"]


def test_empty_chat_rejected(workflow):
    with pytest.raises(ValueError):
        workflow.chat("")


def test_redacts_cloud_evidence(anomaly):
    anomaly["message"] = "password=hello token=abc from 10.1.2.3 to alice@example.test"
    redacted = cloud_event(anomaly)
    assert "source_ip" not in redacted and "user" not in redacted and "ground_truth" not in redacted
    assert "hello" not in redacted["message"] and "abc" not in redacted["message"]
    assert "10.1.2.3" not in redacted["message"] and "alice@example.test" not in redacted["message"]


def test_grounding_rejects_invented_sources(report):
    analysis = Analysis.model_validate({k: report[k] for k in Analysis.model_fields})
    analysis.citations = ["invented.md#chunk-0"]
    with pytest.raises(ValueError):
        AnalysisAgent.validate_grounding(analysis, report["sources"])
