"""PhishLens analysis package."""

from .attachment_analysis import analyze_attachments
from .email_parser import parse_email
from .explanation_generator import generate_explanation
from .linguistic_analysis import analyze_linguistic
from .risk_engine import analyze_email, combine_risk_scores
from .technical_analysis import analyze_technical
from .url_analysis import analyze_urls

__all__ = [
    "analyze_attachments",
    "analyze_email",
    "analyze_linguistic",
    "analyze_technical",
    "analyze_urls",
    "combine_risk_scores",
    "generate_explanation",
    "parse_email",
]
