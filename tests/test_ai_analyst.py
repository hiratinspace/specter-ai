from unittest.mock import MagicMock, patch

from specter_ai.core import ai_analyst


def make_aggregated():
    return {"meta": {"target": "example.com", "scan_mode": "quick", "scanned_at": "2026-01-01 00:00 UTC"}}


def test_missing_api_key_returns_error_dict(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = ai_analyst.run_ai_analysis(make_aggregated())
    assert result["risk_level"] == "unknown"
    assert "error" in result


def test_successful_tool_use_response_is_used_directly(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    fake_tool_use = MagicMock()
    fake_tool_use.type = "tool_use"
    fake_tool_use.input = {
        "executive_summary": "Test summary.",
        "risk_level": "medium",
        "key_findings": [{"title": "Test finding", "severity": "medium", "description": "desc"}],
        "next_steps": [{"step": "Investigate", "priority": "high", "detail": "do it"}],
    }
    fake_message = MagicMock()
    fake_message.content = [fake_tool_use]

    with patch("specter_ai.core.ai_analyst.anthropic.Anthropic") as mock_client:
        mock_client.return_value.messages.create.return_value = fake_message
        result = ai_analyst.run_ai_analysis(make_aggregated())

    assert result["risk_level"] == "medium"
    assert result["executive_summary"] == "Test summary."
    assert "error" not in result


def test_api_exception_returns_error_dict(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    with patch("specter_ai.core.ai_analyst.anthropic.Anthropic") as mock_client:
        mock_client.return_value.messages.create.side_effect = RuntimeError("network down")
        result = ai_analyst.run_ai_analysis(make_aggregated())

    assert result["risk_level"] == "unknown"
    assert "network down" in result["error"]


def test_missing_tool_use_block_returns_error_dict(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    fake_message = MagicMock()
    fake_message.content = []  # no tool_use block at all

    with patch("specter_ai.core.ai_analyst.anthropic.Anthropic") as mock_client:
        mock_client.return_value.messages.create.return_value = fake_message
        result = ai_analyst.run_ai_analysis(make_aggregated())

    assert result["risk_level"] == "unknown"
    assert "error" in result


def test_prompt_truncates_large_payloads():
    huge_data = {**make_aggregated(), "blob": "a" * 20000}
    prompt = ai_analyst.build_analysis_prompt(huge_data)
    assert "[truncated for brevity]" in prompt
