"""
ai_analyst.py — AI-Powered Security Analysis via Claude API
Sends aggregated recon data to Claude and gets structured findings + recommendations.

Sample usage:
    from core.ai_analyst import run_ai_analysis
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

Your job is to analyze automated recon data and provide a sharp, actionable security assessment.

Your output must be structured JSON with exactly these keys:
{
  "executive_summary": "2-3 sentence plain-English summary of overall risk posture",
  "risk_level": "critical | high | medium | low | informational",
  "key_findings": [
    {
      "title": "Short finding title",
      "severity": "critical | high | medium | low | info",
      "description": "What you found and why it matters",
      "evidence": "Specific data from the recon results that supports this finding"
    }
  ],
  "attack_surface": "1-2 sentences describing the total exposed attack surface",
  "next_steps": [
    {
      "step": "Short action title",
      "priority": "immediate | high | medium",
      "detail": "Specific, actionable instruction for a pentester to follow up",
      "tool_suggestion": "Suggested tool or command (e.g. nmap, sqlmap, nikto, hydra)"
    }
  ],
  "interesting_observations": ["Any noteworthy observations that aren't strictly findings"]
}

Rules:
- Be specific — reference actual ports, headers, technologies from the data
- Don't invent findings not supported by the data
- next_steps must be 3-5 items, ordered by priority
- Always respond with valid JSON only — no markdown, no preamble
"""


def build_analysis_prompt(data):
    """Build the user prompt with the recon data."""
    # Trim SANs and keep only what's useful for analysis
    trimmed = json.dumps(data, indent=2, default=str)

    # Cap prompt size to avoid token limits
    if len(trimmed) > 15000:
        trimmed = trimmed[:15000] + "\n... [truncated for brevity]"

    return f"""Analyze the following automated recon results and return your structured JSON assessment.

TARGET: {data['meta']['target']}
SCAN MODE: {data['meta']['scan_mode']}
SCANNED AT: {data['meta']['scanned_at']}

RECON DATA:
{trimmed}
"""


def parse_ai_response(text):
    """Extract and parse JSON from the AI response."""
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
    return json.loads(text)


def run_ai_analysis(aggregated_data):
    """
    Send recon data to Claude API and return structured analysis.

    Returns dict with AI analysis, or an error dict if unavailable.
    """
    if not HAS_ANTHROPIC:
        return {
            "error": "anthropic library not installed — run: pip install anthropic",
            "executive_summary": "AI analysis unavailable.",
            "risk_level": "unknown",
            "key_findings": [],
            "next_steps": [],
        }

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "error": "ANTHROPIC_API_KEY environment variable not set",
            "executive_summary": "AI analysis unavailable — set ANTHROPIC_API_KEY.",
            "risk_level": "unknown",
            "key_findings": [],
            "next_steps": [],
        }

    client = anthropic.Anthropic(api_key=api_key)

    raw_text = ""
    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": build_analysis_prompt(aggregated_data)
                }
            ]
        )

        raw_text = message.content[0].text
        analysis = parse_ai_response(raw_text)
        analysis["_raw"] = raw_text  # keep raw for debugging
        return analysis

    except json.JSONDecodeError as e:
        return {
            "error": f"Failed to parse AI response as JSON: {e}",
            "executive_summary": "AI response could not be parsed.",
            "risk_level": "unknown",
            "key_findings": [],
            "next_steps": [],
            "_raw": raw_text,
        }
    except Exception as e:
        return {
            "error": f"AI analysis failed: {e}",
            "executive_summary": "AI analysis encountered an error.",
            "risk_level": "unknown",
            "key_findings": [],
            "next_steps": [],
        }