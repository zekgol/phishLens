from __future__ import annotations

from typing import Any

from .attachment_analysis import analyze_attachments
from .email_parser import parse_email
from .explanation_generator import generate_explanation
from .linguistic_analysis import analyze_linguistic
from .technical_analysis import analyze_technical
from .url_analysis import analyze_urls


def combine_risk_scores(
    linguistic_risk_score: float,
    authentication_risk_score: float,
    url_risk_score: float,
    attachment_risk_score: float,
) -> int:
    weighted_score = (
        0.4 * float(linguistic_risk_score)
        + 0.3 * float(authentication_risk_score)
        + 0.2 * float(url_risk_score)
        + 0.1 * float(attachment_risk_score)
    )
    return int(round(max(0.0, min(100.0, weighted_score))))


def _risk_level_from_score(score: int) -> str:
    if score <= 29:
        return "Low"
    if score <= 59:
        return "Medium"
    return "High"


def _prediction_from_score(score: int) -> str:
    if score <= 29:
        return "Likely legitimate"
    if score <= 59:
        return "Suspicious"
    return "Likely phishing"


def _collect_top_signals(result: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for category in ("technical", "linguistic", "urls", "attachments"):
        category_items = result.get(category, {}).get("evidence", []) or []
        if category == "linguistic":
            category_items = result.get(category, {}).get("detected_cues", []) or []
        for item in category_items:
            candidate = dict(item)
            candidate["category"] = category
            items.append(candidate)
    items.sort(key=lambda item: item.get("points", 0), reverse=True)
    return items[:limit]


def analyze_email(email_text: str, mode: str = "auto") -> dict[str, Any]:
    parsed_email = parse_email(email_text, mode=mode)
    linguistic = analyze_linguistic(parsed_email.get("body_text", ""))
    technical = analyze_technical(parsed_email)
    urls = analyze_urls(parsed_email.get("body_text", ""))
    attachments = analyze_attachments(parsed_email.get("attachments", []))

    final_score = combine_risk_scores(
        linguistic.get("linguistic_risk_score", 0),
        technical.get("authentication_risk_score", 0),
        urls.get("url_risk_score", 0),
        attachments.get("attachment_risk_score", 0),
    )

    result = {
        "mode": parsed_email.get("mode", mode),
        "parsed_email": parsed_email,
        "linguistic": linguistic,
        "technical": technical,
        "urls": urls,
        "attachments": attachments,
        "final_score": final_score,
        "risk_level": _risk_level_from_score(final_score),
        "prediction": _prediction_from_score(final_score),
        "weights": {
            "linguistic": 0.4,
            "technical": 0.3,
            "urls": 0.2,
            "attachments": 0.1,
        },
    }
    result["top_signals"] = _collect_top_signals(result)
    result.update(generate_explanation(result))
    return result
