from __future__ import annotations

import re
import unicodedata
from typing import Any


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.lower()


RULES = [
    (
        "Urgency",
        10,
        "Creates time pressure or threatens account disruption.",
        [
            "urgent",
            "immediately",
            "within 24 hours",
            "final warning",
            "account suspended",
            "action required",
            "immediate action required",
            "your access will expire",
            "your account will be closed",
            "natychmiast",
            "pilne",
            "ostatnie ostrzeżenie",
            "konto zostanie zawieszone",
            "wymagane działanie",
            "dostęp wygaśnie",
        ],
    ),
    (
        "Credential / payment / verification request",
        12,
        "Asks the user to confirm credentials, payment details, identity, or documents.",
        [
            "verify your account",
            "confirm your password",
            "update payment",
            "upload documents",
            "login to continue",
            "sign in to verify",
            "payment failed",
            "billing issue",
            "confirm your identity",
            "password reset required",
            "potwierdź konto",
            "hasło",
            "płatność",
            "dokumenty",
            "zaloguj się",
            "potwierdź tożsamość",
            "problem z płatnością",
            "aktualizacja danych",
        ],
    ),
    (
        "Vague institutional wording",
        7,
        "Uses generic institutional language instead of a verifiable sender identity.",
        [
            "security department",
            "support team",
            "system administrator",
            "account team",
            "compliance department",
            "it service desk",
            "mailbox administrator",
            "dział bezpieczeństwa",
            "administrator systemu",
            "zespół wsparcia",
            "dział zgodności",
            "obsługa konta",
            "administrator poczty",
        ],
    ),
    (
        "Pressure / fear",
        12,
        "Uses threat language or fear of loss to trigger a quick reaction.",
        [
            "your account will be blocked",
            "failure to respond",
            "restricted access",
            "unauthorized login detected",
            "unusual activity detected",
            "legal action",
            "account limitation",
            "konto zostanie zablokowane",
            "brak odpowiedzi",
            "ograniczony dostęp",
            "wykryto nietypową aktywność",
            "wykryto nieautoryzowane logowanie",
        ],
    ),
    (
        "Suspicious politeness / manipulation",
        7,
        "Uses overly polite language to pressure the recipient into compliance.",
        [
            "we kindly ask you",
            "thank you for your immediate cooperation",
            "please treat this as urgent",
            "we appreciate your quick response",
            "prosimy uprzejmie",
            "dziękujemy za szybką reakcję",
            "prosimy potraktować to jako pilne",
        ],
    ),
]


def analyze_linguistic(body_text: str) -> dict[str, Any]:
    text = body_text or ""
    normalized_text = _normalize(text)
    cues: list[dict[str, Any]] = []
    suspicious_phrases: list[str] = []
    total_points = 0

    for category, base_points, reason, phrases in RULES:
        for phrase in phrases:
            normalized_phrase = _normalize(phrase)
            if normalized_phrase and normalized_phrase in normalized_text:
                points = base_points
                if len(normalized_phrase.split()) >= 4:
                    points += 2
                if re.search(r"\d", normalized_phrase):
                    points += 1
                cues.append(
                    {
                        "category": category,
                        "matched_text": phrase,
                        "reason": reason,
                        "points": points,
                    }
                )
                suspicious_phrases.append(phrase)
                total_points += points

    linguistic_risk_score = max(0, min(100, total_points))

    return {
        "linguistic_risk_score": linguistic_risk_score,
        "detected_cues": cues,
        "suspicious_phrases": sorted(set(suspicious_phrases)),
    }
