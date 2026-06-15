from __future__ import annotations

import re
from typing import Any
from email.utils import parseaddr

from .email_parser import parse_address_domain


AUTH_PATTERN = re.compile(r"\b(?P<mechanism>spf|dkim|dmarc)=(?P<result>pass|fail|softfail|neutral|none|unknown)\b", re.IGNORECASE)
MESSAGE_ID_DOMAIN_PATTERN = re.compile(r"<[^@<>\s]+@([^<>\s>]+)>")


def _extract_domain(value: str) -> str:
    return parse_address_domain(value)


def _extract_message_id_domain(value: str) -> str:
    if not value:
        return ""
    match = MESSAGE_ID_DOMAIN_PATTERN.search(value)
    if match:
        return match.group(1).strip().lower()
    if "@" in value and ">" not in value:
        return value.rsplit("@", 1)[-1].strip(" >").lower()
    return ""


def _parse_authentication_results(auth_headers: list[str]) -> dict[str, str]:
    parsed = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for header in auth_headers:
        for match in AUTH_PATTERN.finditer(header.lower()):
            mechanism = match.group("mechanism")
            result = match.group("result")
            parsed[mechanism] = result
    return parsed


def analyze_technical(parsed_email: dict[str, Any]) -> dict[str, Any]:
    auth_headers = parsed_email.get("authentication_results", []) or []
    received_headers = parsed_email.get("received_headers", []) or []

    from_value = parsed_email.get("from", "") or ""
    reply_to_value = parsed_email.get("reply_to", "") or ""
    return_path_value = parsed_email.get("return_path", "") or ""
    message_id_value = parsed_email.get("message_id", "") or ""
    subject_value = parsed_email.get("subject", "") or ""

    from_domain = _extract_domain(from_value)
    reply_to_domain = _extract_domain(reply_to_value)
    return_path_domain = _extract_domain(return_path_value)
    message_id_domain = _extract_message_id_domain(message_id_value)

    authentication = _parse_authentication_results(auth_headers)
    evidence: list[dict[str, Any]] = []
    total_points = 0

    def add_evidence(signal: str, value: str, risk: str, explanation: str, points: int) -> None:
        nonlocal total_points
        evidence.append(
            {
                "signal": signal,
                "value": value,
                "risk": risk,
                "explanation": explanation,
                "points": points,
            }
        )
        total_points += points

    spf_result = authentication.get("spf", "none")
    dkim_result = authentication.get("dkim", "none")
    dmarc_result = authentication.get("dmarc", "none")

    if spf_result == "fail":
        add_evidence("SPF", spf_result, "high", "The sender failed SPF alignment checks.", 20)
    elif spf_result in {"softfail", "neutral"}:
        add_evidence("SPF", spf_result, "medium", "SPF did not produce a clean pass.", 10)

    if dkim_result == "fail":
        add_evidence("DKIM", dkim_result, "high", "The message did not pass DKIM validation.", 20)
    elif dkim_result in {"softfail", "neutral"}:
        add_evidence("DKIM", dkim_result, "medium", "DKIM did not produce a clean pass.", 10)

    if dmarc_result == "fail":
        add_evidence("DMARC", dmarc_result, "high", "DMARC failed, which weakens sender authenticity.", 30)
    elif dmarc_result == "none":
        add_evidence("DMARC", dmarc_result, "medium", "DMARC was not reported in the authentication results.", 10)

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        add_evidence(
            "From vs Reply-To",
            f"{from_domain} != {reply_to_domain}",
            "high",
            "The visible sender domain does not match the reply-to domain.",
            20,
        )

    if from_domain and return_path_domain and from_domain != return_path_domain:
        add_evidence(
            "From vs Return-Path",
            f"{from_domain} != {return_path_domain}",
            "medium",
            "The bounce address domain differs from the visible sender domain.",
            15,
        )

    if from_domain and message_id_domain and from_domain != message_id_domain:
        add_evidence(
            "Message-ID domain mismatch",
            f"{from_domain} != {message_id_domain}",
            "medium",
            "The Message-ID domain does not match the visible sender domain.",
            10,
        )

    if not auth_headers:
        add_evidence(
            "Authentication-Results missing",
            "none",
            "medium",
            "The message does not include Authentication-Results headers.",
            10,
        )

    if len(received_headers) < 2:
        add_evidence(
            "Received headers",
            str(len(received_headers)),
            "low",
            "A raw email should usually include multiple Received headers; very few can be a warning sign.",
            5,
        )

    authentication_risk_score = max(0, min(100, total_points))

    extracted_technical_fields = {
        "from": from_value,
        "reply_to": reply_to_value,
        "return_path": return_path_value,
        "message_id": message_id_value,
        "subject": subject_value,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "message_id_domain": message_id_domain,
        "authentication_results": authentication,
        "received_header_count": len(received_headers),
    }

    return {
        "authentication_risk_score": authentication_risk_score,
        "extracted_technical_fields": extracted_technical_fields,
        "evidence": evidence,
        "summary_note": (
            "SPF, DKIM, and DMARC are useful signals, but they are not perfect. A phishing email can still pass authentication if it comes from a compromised or attacker-owned legitimate domain."
        ),
    }
