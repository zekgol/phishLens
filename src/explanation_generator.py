from __future__ import annotations

from typing import Any


def _top_evidence(result: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    evidence_items: list[dict[str, Any]] = []
    for category in ("technical", "linguistic", "urls", "attachments"):
        items = result.get(category, {}).get("evidence", []) or []
        if category == "linguistic":
            items = result.get(category, {}).get("detected_cues", []) or []
        for item in items:
            normalized = dict(item)
            normalized["category"] = category
            evidence_items.append(normalized)
    evidence_items.sort(key=lambda item: item.get("points", 0), reverse=True)
    return evidence_items[:limit]


def _format_signal(item: dict[str, Any]) -> str:
    category = item.get("category", "signal")
    if category == "technical":
        return f"{item.get('signal', 'Technical signal')}: {item.get('explanation', '')}"
    if category == "linguistic":
        return f"{item.get('category', 'Linguistic')} cue '{item.get('matched_text', '')}'"
    if category == "urls":
        return f"URL issue '{item.get('issue', '')}' for {item.get('url', '')}"
    if category == "attachments":
        return f"Attachment issue '{item.get('issue', '')}' for {item.get('filename', '')}"
    return str(item)


def generate_explanation(analysis_result: dict[str, Any]) -> dict[str, str]:
    score = int(round(analysis_result.get("final_score", 0)))
    risk_level = analysis_result.get("risk_level", "Low")
    prediction = analysis_result.get("prediction", "Likely legitimate")
    top_items = _top_evidence(analysis_result, limit=4)

    if top_items:
        evidence_text = ", ".join(_format_signal(item) for item in top_items[:3])
        plain_explanation = (
            f"This email is classified as {risk_level.lower()} risk because {evidence_text}. "
            "These signals suggest the sender identity and the requested action should be verified before interacting with the message."
        )
    else:
        plain_explanation = (
            f"This email is classified as {risk_level.lower()} risk based on the available signals. "
            "No strong red flags were detected, but this is a decision-support tool rather than a perfect verdict."
        )

    if risk_level == "High":
        safe_action = "Do not click links, open attachments, or reply. Verify the sender through a known trusted channel before taking any action."
    elif risk_level == "Medium":
        safe_action = "Pause before responding, inspect links carefully, and verify the request with the organization using a separate trusted contact method."
    else:
        safe_action = "The message looks relatively normal, but still verify unexpected requests and avoid entering credentials from email links."

    investor_summary = (
        f"PhishLens combines language cues, header authentication, URL inspection, and attachment metadata into one transparent risk score ({score}/100) so users can triage suspicious email quickly without external APIs."
    )

    technical_summary = (
        f"Final classification: {prediction}. The model uses rule-based evidence from linguistic patterns, Authentication-Results, header mismatches, URL/domain reputation heuristics, and attachment filename analysis. It is explainable and offline, but it should be treated as a triage assistant rather than ground truth."
    )

    plain_english_summary = (
        "In plain English, PhishLens highlights why an email looks risky so a person can check the sender, link, and attachment before acting."
    )

    return {
        "plain_explanation": plain_explanation,
        "recommended_safe_action": safe_action,
        "investor_summary": investor_summary,
        "technical_summary": technical_summary,
        "plain_english_summary": plain_english_summary,
    }
