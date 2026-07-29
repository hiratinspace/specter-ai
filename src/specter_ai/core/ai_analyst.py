"""
ai_analyst.py — AI-Powered Security Analysis via Claude API
Sends aggregated recon data to Claude and gets structured findings +
recommendations back via tool-use (forced structured output), so responses
are always well-formed — no free-text JSON parsing to fail.

Sample usage:
    from specter_ai.core.ai_analyst import run_ai_analysis
    analysis = run_ai_analysis(aggregated_data)
"""

import json
import os

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


SYSTEM_PROMPT = """You are a senior penetration tester with 15 years of experience in offensive security,
red team operations, and vulnerability assessment. You think like an attacker.

Your job is to analyze automated recon data and provide a sharp, actionable security
assessment by calling the submit_assessment tool exactly once with your findings.

Rules:
- Be specific — reference actual ports, headers, technologies from the data
- Don't invent findings not supported by the data
- next_steps must be 3-5 items, ordered by priority
"""

ASSESSMENT_TOOL = {
    "name": "submit_assessment",
    "description": "Submit a structured security assessment of the recon data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "2-3 sentence plain-English summary of overall risk posture",
            },
            "risk_level": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "informational"],
            },
            "key_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title":       {"type": "string", "description": "Short finding title"},
                        "severity":    {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "description": {"type": "string", "description": "What you found and why it matters"},
                        "evidence":    {"type": "string", "description": "Specific data from the recon results that supports this finding"},
                    },
                    "required": ["title", "severity", "description"],
                },
            },
            "attack_surface": {
                "type": "string",
                "description": "1-2 sentences describing the total exposed attack surface",
            },
            "next_steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "step":            {"type": "string", "description": "Short action title"},
                        "priority":        {"type": "string", "enum": ["immediate", "high", "medium"]},
                        "detail":          {"type": "string", "description": "Specific, actionable instruction for a pentester to follow up"},
                        "tool_suggestion": {"type": "string", "description": "Suggested tool or command (e.g. nmap, sqlmap, nikto, hydra)"},
                    },
                    "required": ["step", "priority", "detail"],
                },
            },
            "interesting_observations": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Any noteworthy observations that aren't strictly findings",
            },
        },
        "required": ["executive_summary", "risk_level", "key_findings", "next_steps"],
    },
}


def build_analysis_prompt(data):
    """Build the user prompt with the recon data."""
    trimmed = json.dumps(data, indent=2, default=str)

    # Cap prompt size to avoid token limits
    if len(trimmed) > 15000:
        trimmed = trimmed[:15000] + "\n... [truncated for brevity]"

    return f"""Analyze the following automated recon results and call submit_assessment with your structured assessment.

TARGET: {data['meta']['target']}
SCAN MODE: {data['meta']['scan_mode']}
SCANNED AT: {data['meta']['scanned_at']}

RECON DATA:
{trimmed}
"""


def _error_result(message):
    return {
        "error": message,
        "executive_summary": "AI analysis unavailable.",
        "risk_level": "unknown",
        "key_findings": [],
        "next_steps": [],
    }


def run_ai_analysis(aggregated_data):
    """
    Send recon data to Claude API and return structured analysis.

    Returns dict with AI analysis, or an error dict if unavailable.
    """
    if not HAS_ANTHROPIC:
        return _error_result("anthropic library not installed — run: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _error_result("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            tools=[ASSESSMENT_TOOL],
            tool_choice={"type": "tool", "name": "submit_assessment"},
            messages=[
                {
                    "role": "user",
                    "content": build_analysis_prompt(aggregated_data)
                }
            ]
        )

        tool_use = next((b for b in message.content if b.type == "tool_use"), None)
        if tool_use is None:
            return _error_result("Claude did not return a structured assessment")

        analysis = dict(tool_use.input)
        analysis.setdefault("key_findings", [])
        analysis.setdefault("next_steps", [])
        return analysis

    except Exception as e:
        return _error_result(f"AI analysis failed: {e}")
