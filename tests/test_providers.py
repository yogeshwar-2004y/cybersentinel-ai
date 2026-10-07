"""Mock transport tests exercise all providers without credentials or billable requests."""

from dataclasses import replace
import json
import pytest
from llm.provider import OpenAIProvider, GeminiProvider, OllamaProvider, ProviderError
from agents.analysis_agent import AnalysisAgent
from agents.detection_agent import DetectionAgent
from agents.threat_agent import ThreatIntelligenceAgent


@pytest.mark.parametrize("kind", [OpenAIProvider, GeminiProvider, OllamaProvider])
def test_provider_contract(config, monkeypatch, kind):
    config = replace(config, openai_key="test-openai", gemini_key="test-gemini")
    provider = kind(config)
    captured = {}

    def post(url, payload, headers=None):
        captured.update(url=url, payload=payload, headers=headers)
        if kind == OpenAIProvider:
            return {"choices": [{"message": {"content": '{"ok":true}'}, "finish_reason": "stop"}]}
        if kind == GeminiProvider:
            return {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": '{"ok":true}'}]}}]}
        return {"done": True, "message": {"content": '{"ok":true}'}}

    monkeypatch.setattr(provider, "post", post)
    assert json.loads(provider.complete("system", "JSON incident", True)) == {"ok": True}
    if kind == OpenAIProvider:
        assert captured["payload"]["response_format"]["type"] == "json_object"
    if kind == GeminiProvider:
        assert captured["headers"]["x-goog-api-key"] == "test-gemini" and "key=" not in captured["url"]
    if kind == OllamaProvider:
        assert captured["payload"]["stream"] is False and captured["payload"]["format"] == "json"


@pytest.mark.parametrize("kind", [OpenAIProvider, GeminiProvider])
def test_missing_keys_fail(config, kind):
    config = replace(config, openai_key="", gemini_key="")
    with pytest.raises(ProviderError):
        kind(config).complete("system", "JSON", True)


def payload(workflow, anomaly):
    return ThreatIntelligenceAgent(workflow.retriever).execute(DetectionAgent().execute({"event": anomaly}))


def test_cloud_optin_prevents_transport(config, workflow, anomaly, monkeypatch):
    provider = OpenAIProvider(config)

    def forbidden(*args):
        pytest.fail("Cloud call happened without consent")

    monkeypatch.setattr(provider, "complete", forbidden)
    result = AnalysisAgent(config, provider).run(payload(workflow, anomaly))
    assert result["analysis_provider"] == "local" and "disabled" in result["fallback_reason"]


def test_malformed_json_fallback(config, workflow, anomaly, monkeypatch):
    config = replace(config, allow_cloud_logs=True)
    provider = OpenAIProvider(config)
    monkeypatch.setattr(provider, "complete", lambda *args: '{"nonsense":true}')
    result = AnalysisAgent(config, provider).run(payload(workflow, anomaly))
    assert result["analysis_provider"] == "local" and result["fallback_reason"]


def test_successful_remote_analysis(config, workflow, anomaly, monkeypatch):
    config = replace(config, allow_cloud_logs=True)
    provider = OpenAIProvider(config)
    agent = AnalysisAgent(config, provider)
    p = payload(workflow, anomaly)
    valid = agent.local_analysis(p).model_dump()
    monkeypatch.setattr(provider, "complete", lambda *args: json.dumps(valid))
    result = agent.run(p)
    assert result["analysis_provider"] == "openai" and not result["fallback_reason"]


def test_strict_mode_disables_fallback(config, workflow, anomaly):
    config = replace(config, allow_fallback=False)
    with pytest.raises(ProviderError):
        AnalysisAgent(config, OpenAIProvider(config)).run(payload(workflow, anomaly))


def test_network_error_redacts_key(config, monkeypatch):
    import requests
    from llm import provider as module

    monkeypatch.setattr(module.time, "sleep", lambda _: None)

    def failure(*args, **kwargs):
        raise requests.ConnectionError("URL secret-key-value")

    monkeypatch.setattr(module.requests, "post", failure)
    adapter = OpenAIProvider(replace(config, openai_key="secret-key-value"))
    with pytest.raises(ProviderError) as exc:
        adapter.complete("system", "JSON", True)
    assert "secret-key-value" not in str(exc.value)
