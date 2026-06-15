from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import Parser
from email.utils import parseaddr
from typing import Any


HEADER_FIELDS = [
    "From",
    "Reply-To",
    "Return-Path",
    "Message-ID",
    "Subject",
    "Authentication-Results",
]


def _decode_part_text(part: Message) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    if isinstance(content, bytes):
        charset = part.get_content_charset() or "utf-8"
        return content.decode(charset, errors="replace")
    return str(content)


def _extract_body_from_message(message: Message) -> str:
    if message.is_multipart():
        text_parts: list[str] = []
        html_parts: list[str] = []
        for part in message.walk():
            if part.is_multipart():
                continue
            content_disposition = (part.get_content_disposition() or "").lower()
            content_type = (part.get_content_type() or "").lower()
            if content_disposition == "attachment":
                continue
            if content_type == "text/plain":
                text_parts.append(_decode_part_text(part).strip())
            elif content_type == "text/html":
                html_parts.append(_decode_part_text(part).strip())
        if text_parts:
            return "\n\n".join(part for part in text_parts if part)
        if html_parts:
            import re

            html_text = "\n\n".join(part for part in html_parts if part)
            html_text = re.sub(r"<[^>]+>", " ", html_text)
            html_text = re.sub(r"\s+", " ", html_text)
            return html_text.strip()
        return ""

    return _decode_part_text(message).strip()


def _extract_attachments(message: Message) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        content_disposition = (part.get_content_disposition() or "").lower()
        if not filename and content_disposition != "attachment":
            continue
        payload = part.get_payload(decode=True)
        size_bytes = len(payload) if payload else 0
        attachments.append(
            {
                "filename": filename or "unnamed attachment",
                "content_type": part.get_content_type(),
                "content_disposition": content_disposition or "attachment",
                "size_bytes": size_bytes,
            }
        )
    return attachments


def _empty_technical_fields() -> dict[str, Any]:
    return {
        "from": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "subject": "",
        "authentication_results": [],
        "received_headers": [],
        "attachments": [],
    }


def parse_email(email_text: str, mode: str = "auto") -> dict[str, Any]:
    """Parse body-only or raw email content into a structured dictionary."""

    email_text = email_text or ""
    normalized_mode = (mode or "auto").strip().lower()

    if normalized_mode == "body":
        return {
            "mode": "body_only",
            "from": "",
            "reply_to": "",
            "return_path": "",
            "message_id": "",
            "subject": "",
            "authentication_results": [],
            "received_headers": [],
            "body_text": email_text.strip(),
            "attachments": [],
            "raw_headers": {},
            "parsed_message": None,
        }

    parser = Parser(policy=policy.default)
    message = parser.parsestr(email_text)
    has_headers = any(message.get(field) for field in HEADER_FIELDS) or bool(message.keys())

    if normalized_mode == "auto" and not has_headers:
        return {
            "mode": "body_only",
            "from": "",
            "reply_to": "",
            "return_path": "",
            "message_id": "",
            "subject": "",
            "authentication_results": [],
            "received_headers": [],
            "body_text": email_text.strip(),
            "attachments": [],
            "raw_headers": {},
            "parsed_message": None,
        }

    headers = {
        "from": message.get("From", "").strip(),
        "reply_to": message.get("Reply-To", "").strip(),
        "return_path": message.get("Return-Path", "").strip(),
        "message_id": message.get("Message-ID", "").strip(),
        "subject": message.get("Subject", "").strip(),
        "authentication_results": [value.strip() for value in message.get_all("Authentication-Results", []) if value.strip()],
        "received_headers": [value.strip() for value in message.get_all("Received", []) if value.strip()],
        "attachments": _extract_attachments(message),
    }

    parsed = {
        "mode": "raw_email",
        **headers,
        "body_text": _extract_body_from_message(message),
        "raw_headers": {key: message.get_all(key, []) for key in message.keys()},
        "parsed_message": message,
    }

    return parsed


def parse_address_domain(value: str) -> str:
    """Extract a domain from a mail header address value."""

    _name, address = parseaddr(value or "")
    if "@" not in address:
        return ""
    return address.split("@", 1)[1].strip().lower()
