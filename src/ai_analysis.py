from __future__ import annotations

import json
import os
import re
from typing import Any

import streamlit as st

try:
    from google import genai
    from google.genai import types
except Exception:  # pragma: no cover - optional dependency
    genai = None
    types = None


MODEL_NAME = "gemini-2.0-flash"
SYSTEM_INSTRUCTION = (
    "You are a defensive cybersecurity assistant. You explain phishing risk based only on the provided evidence. "
    "Do not invent indicators. Do not visit URLs. Do not provide offensive instructions. Do not encourage the user to click suspicious links. "
    "Return clear, concise JSON only."
)


def get_api_key() -> str | None:
    try:
        key = st.secrets.get("GEMINI_API_KEY")
        if key:
            return str(key).strip() or None
    except Exception:
        pass

    key = os.getenv("GEMINI_API_KEY")
    return key.strip() if key and key.strip() else None


def is_ai_available() -> bool:
    return get_api_key() is not None


def _safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _sanitize_evidence(items: list[dict[str, Any]] | None, allowed_fields: list[str]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        clean_item: dict[str, Any] = {}
        for field in allowed_fields:
            value = item.get(field)
            if value not in (None, "", [], {}):
                clean_item[field] = value
        if clean_item:
            sanitized.append(clean_item)
    return sanitized


def build_sanitized_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "final_risk_score": int(result.get("final_score", 0) or 0),
        "final_risk_level": _safe_text(result.get("risk_level"), "Low"),
        "prediction": _safe_text(result.get("prediction"), "Likely legitimate"),
        "linguistic_evidence": _sanitize_evidence(
            result.get("linguistic", {}).get("detected_cues", []),
            ["category", "matched_text", "reason", "points"],
        ),
        "technical_header_evidence": _sanitize_evidence(
            result.get("technical", {}).get("evidence", []),
            ["signal", "value", "risk", "explanation", "points"],
        ),
        "url_domain_evidence": _sanitize_evidence(
            result.get("urls", {}).get("evidence", []),
            ["issue", "url", "domain", "risk", "explanation", "points"],
        ),
        "attachment_evidence": _sanitize_evidence(
            result.get("attachments", {}).get("evidence", []),
            ["issue", "filename", "risk", "explanation", "points"],
        ),
    }


def _local_fallback(result: dict[str, Any], reason: str) -> dict[str, str]:
    score = int(result.get("final_score", 0) or 0)
    risk_level = _safe_text(result.get("risk_level"), "Low")
    prediction = _safe_text(result.get("prediction"), "Likely legitimate")

    plain_english = _safe_text(
        result.get("plain_explanation") or result.get("plain_english_summary"),
        f"This email looks like a {risk_level.lower()} risk message. The local rule-based engine is still the source of truth.",
    )
    technical_summary = _safe_text(
        result.get("technical_summary"),
        f"Final classification: {prediction}. The rule-based engine combines language, header, URL, and attachment evidence into a {score}/100 triage score.",
    )
    safe_action = _safe_text(
        result.get("recommended_safe_action"),
        "Do not click links, open attachments, or reply until the sender and request are independently verified.",
    )
    limitation_note = (
        f"Gemini explanation unavailable ({reason}). This is a decision-support summary only; the rule-based engine remains the source of truth."
    )
    return {
        "plain_english_explanation": plain_english,
        "technical_summary": technical_summary,
        "recommended_safe_action": safe_action,
        "limitation_note": limitation_note,
    }


def _strip_json_fences(text: str) -> str:
    stripped = text.strip()
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.IGNORECASE | re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()
    return stripped


def _coerce_ai_output(data: dict[str, Any], result: dict[str, Any]) -> dict[str, str]:
    fallback = _local_fallback(result, "invalid or incomplete Gemini response")
    if not isinstance(data, dict):
        return fallback

    output = {
        "plain_english_explanation": _safe_text(data.get("plain_english_explanation"), fallback["plain_english_explanation"]),
        "technical_summary": _safe_text(data.get("technical_summary"), fallback["technical_summary"]),
        "recommended_safe_action": _safe_text(data.get("recommended_safe_action"), fallback["recommended_safe_action"]),
        "limitation_note": _safe_text(data.get("limitation_note"), fallback["limitation_note"]),
    }
    return output


def generate_ai_explanation(result: dict[str, Any]) -> dict[str, str]:
    fallback = _local_fallback(result, "Gemini integration unavailable")
    api_key = get_api_key()
    if not api_key:
        return fallback

    if genai is None or types is None:
        return _local_fallback(result, "google-genai package is not installed")

    payload = build_sanitized_payload(result)
    prompt = (
        f"{SYSTEM_INSTRUCTION}\n\n"
        "The rule-based engine is the source of truth. Do not change the risk score. "
        "Use only the structured evidence below. Do not mention raw email content, headers that were not provided, or any URL that was not explicitly included. "
        "Explain the existing evidence clearly in simple language for a general audience and also summarize the technical signals for a security audience. "
        "Do not write a pitch summary. Provide a recommended safe action. "
        "Use short, clear sentences and avoid jargon when possible. "
        "Explicitly note that this is decision support, not a perfect verdict. "
        "Return JSON with these exact keys: plain_english_explanation, technical_summary, recommended_safe_action, limitation_note.\n\n"
        f"Structured analysis evidence:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json",
            ),
        )
        response_text = _safe_text(getattr(response, "text", ""))
        if not response_text:
            return _local_fallback(result, "empty Gemini response")

        try:
            parsed = json.loads(_strip_json_fences(response_text))
        except json.JSONDecodeError:
            return _local_fallback(result, "invalid JSON returned by Gemini")

        return _coerce_ai_output(parsed, result)
    except Exception as exc:  # pragma: no cover - defensive fallback
        message = str(exc).strip() or exc.__class__.__name__
        lowered = message.lower()
        if "rate" in lowered or "quota" in lowered or "429" in lowered:
            reason = "Gemini rate limit or quota error"
        else:
            reason = f"Gemini API failure: {message}"
        return _local_fallback(result, reason)