from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Any


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".iso",
    ".img",
    ".jar",
    ".docm",
    ".xlsm",
    ".zip",
    ".rar",
    ".7z",
    ".html",
    ".hta",
    ".lnk",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
DANGEROUS_DOUBLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".lnk"}


def _filename_suffixes(filename: str) -> list[str]:
    windows_path = PureWindowsPath(filename)
    unix_path = PurePosixPath(filename)
    suffixes = windows_path.suffixes or unix_path.suffixes
    return [suffix.lower() for suffix in suffixes]


def analyze_attachments(attachments: list[dict[str, Any]] | None) -> dict[str, Any]:
    attachments = attachments or []
    evidence: list[dict[str, Any]] = []
    total_points = 0

    for attachment in attachments:
        filename = str(attachment.get("filename", "") or "unnamed attachment")
        suffixes = _filename_suffixes(filename)
        final_extension = suffixes[-1] if suffixes else ""
        second_last_extension = suffixes[-2] if len(suffixes) >= 2 else ""

        if final_extension in DANGEROUS_DOUBLE_EXTENSIONS and len(suffixes) >= 2:
            points = 25
            evidence.append(
                {
                    "filename": filename,
                    "issue": "Double extension with executable script",
                    "explanation": f"The filename ends with {final_extension} after another extension ({second_last_extension}), which is a common deception pattern.",
                    "points": points,
                }
            )
            total_points += points
            continue

        if final_extension in SUSPICIOUS_EXTENSIONS:
            points = 10 if final_extension not in ARCHIVE_EXTENSIONS else 8
            issue = "Suspicious attachment extension"
            explanation = f"The attachment ends with {final_extension}, which can be risky in email workflows."
            if final_extension in ARCHIVE_EXTENSIONS:
                explanation = f"The attachment is a compressed or disk image file ({final_extension}), which can hide nested content."
            evidence.append(
                {
                    "filename": filename,
                    "issue": issue,
                    "explanation": explanation,
                    "points": points,
                }
            )
            total_points += points
            continue

        if len(suffixes) >= 2 and final_extension not in SUSPICIOUS_EXTENSIONS and second_last_extension in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png"}:
            points = 8
            evidence.append(
                {
                    "filename": filename,
                    "issue": "Unexpected double extension",
                    "explanation": f"The filename uses multiple extensions ending in {final_extension}, which can be used to disguise the true file type.",
                    "points": points,
                }
            )
            total_points += points

    attachment_risk_score = max(0, min(100, total_points))

    return {
        "attachment_risk_score": attachment_risk_score,
        "evidence": evidence,
    }
