"""Streamlit AppTest exercises the real pages with a shared test-session context."""

from pathlib import Path
from streamlit.testing.v1 import AppTest
import pytest


@pytest.mark.parametrize("page", ["dashboard", "incident", "analytics", "reports", "knowledge"])
def test_all_pages_render(page, config, detector, scored, workflow, anomaly):
    # One stored incident exercises populated reports, response, and trace views.
    report = workflow.investigate(anomaly)
    source = f"""
import streamlit as st
from pages.{page} import render
render()
"""
    at = AppTest.from_string(source, default_timeout=30)
    at.session_state["config"] = config
    at.session_state["detector"] = detector
    at.session_state["scored"] = scored
    at.session_state["workflow"] = workflow
    at.session_state["reference_name"] = "Test independent baseline"
    at.session_state["dataset_name"] = "Synthetic test dataset"
    at.session_state["active_incident"] = report["incident_id"]
    at.run()
    assert not at.exception, str(at.exception)


def test_main_navigation(monkeypatch, tmp_path):
    monkeypatch.setenv("EMBEDDING_BACKEND", "hashing")
    monkeypatch.setenv("LLM_PROVIDER", "local")
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    root = Path(__file__).resolve().parents[1]
    at = AppTest.from_file(str(root / "app.py"), default_timeout=30).run()
    assert not at.exception, str(at.exception)
    assert len(at.metric) >= 4
    # Run the real Dashboard workflow action and inspect persisted output.
    button = next(b for b in at.button if b.label == "Run agent investigation")
    button.click().run()
    assert not at.exception
    assert at.session_state["active_incident"].startswith("INC-")


def test_oidc_gate_blocks_dashboard(monkeypatch, tmp_path):
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    root = Path(__file__).resolve().parents[1]
    at = AppTest.from_file(str(root / "app.py"), default_timeout=30).run()
    assert not at.exception
    assert any(b.label == "Sign in" for b in at.button)
    assert not at.metric
