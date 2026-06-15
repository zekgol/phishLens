from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pandas as pd
import streamlit as st

from src.ai_analysis import build_sanitized_payload, generate_ai_explanation, is_ai_available
from src.risk_engine import analyze_email


APP_TITLE = "PhishLens: AI-Powered Email Threat Analysis"
ROOT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT_DIR / "sample_emails"
SAMPLE_FILES = {
    "Phishing raw email": SAMPLES_DIR / "phishing_raw_email.txt",
    "Legitimate raw email": SAMPLES_DIR / "legitimate_raw_email.txt",
    "Phishing body only": SAMPLES_DIR / "phishing_body_only.txt",
    "Legitimate body only": SAMPLES_DIR / "legitimate_body_only.txt",
}


st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")


def _score_color(level: str) -> str:
    return {
        "Low": "#15803d",
        "Medium": "#b45309",
        "High": "#b91c1c",
    }.get(level, "#334155")


def _badge_class(level: str) -> str:
    return {
        "Low": "badge-low",
        "Medium": "badge-medium",
        "High": "badge-high",
    }.get(level, "badge-neutral")


def _metric_card(title: str, value: str, helper: str, accent: str) -> str:
    return dedent(
        f"""
        <div class="metric-card" style="border-top-color: {accent};">
            <div class="metric-title">{title}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-helper">{helper}</div>
        </div>
        """
    )


def _section_header(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <div class="section-header">
            <div class="section-title">{title}</div>
            <div class="section-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _evidence_table(title: str, rows: list[dict], empty_message: str) -> None:
    st.markdown(f"<div class='subsection-title'>{title}</div>", unsafe_allow_html=True)
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info(empty_message)


def _load_sample(sample_key: str) -> None:
    sample_path = SAMPLE_FILES.get(sample_key)
    if sample_path and sample_path.exists():
        st.session_state["email_text"] = sample_path.read_text(encoding="utf-8")
        st.session_state["analysis_result"] = None
        st.session_state["sample_message"] = f"Loaded {sample_key.lower()}"
    else:
        st.session_state["sample_message"] = "Sample file not found."


st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(circle at top right, rgba(31, 111, 145, 0.18), transparent 30%),
            radial-gradient(circle at left center, rgba(18, 95, 83, 0.12), transparent 24%),
            linear-gradient(180deg, #f8fafc 0%, #edf3f7 100%);
        color: #122033;
    }
    .hero {
        padding: 1.35rem 1.45rem 1.15rem 1.45rem;
        border-radius: 1.2rem;
        background: linear-gradient(135deg, #102a43 0%, #163b5a 45%, #2f6f6f 100%);
        color: white;
        border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 18px 44px rgba(16, 42, 67, 0.22);
        margin-bottom: 1rem;
    }
    .hero h1 {
        margin-bottom: 0.35rem;
    }
    .hero p {
        margin: 0.25rem 0 0 0;
        opacity: 0.95;
        font-size: 1.03rem;
        max-width: 960px;
    }
    .hero-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-top: 0.85rem;
    }
    .hero-badge {
        display: inline-block;
        padding: 0.35rem 0.7rem;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.12);
        border: 1px solid rgba(255, 255, 255, 0.18);
        font-size: 0.84rem;
    }
    .panel {
        padding: 1rem;
        border-radius: 1rem;
        background: rgba(255, 255, 255, 0.88);
        border: 1px solid rgba(17, 32, 51, 0.08);
        box-shadow: 0 12px 26px rgba(18, 32, 51, 0.06);
    }
    .score-banner {
        padding: 1rem 1.1rem;
        border-radius: 1rem;
        background: rgba(255, 255, 255, 0.9);
        border: 1px solid rgba(15, 23, 42, 0.08);
        box-shadow: 0 10px 22px rgba(18, 32, 51, 0.06);
        margin-bottom: 0.9rem;
    }
    .section-header {
        display: flex;
        justify-content: space-between;
        align-items: end;
        gap: 1rem;
        margin: 1.2rem 0 0.7rem 0;
    }
    .section-title {
        font-size: 1.14rem;
        font-weight: 800;
        color: #102a43;
    }
    .section-subtitle {
        font-size: 0.92rem;
        color: #5b6b7a;
        text-align: right;
        max-width: 660px;
    }
    .subsection-title {
        font-size: 1rem;
        font-weight: 700;
        margin: 0.95rem 0 0.35rem 0;
        color: #102a43;
    }
    .metric-card {
        padding: 1rem;
        border-radius: 1rem;
        background: rgba(255, 255, 255, 0.92);
        border: 1px solid rgba(17, 32, 51, 0.08);
        border-top: 4px solid #0f766e;
        box-shadow: 0 10px 22px rgba(18, 32, 51, 0.05);
        height: 100%;
    }
    .metric-title {
        font-size: 0.82rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #5b6b7a;
        margin-bottom: 0.35rem;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 800;
        color: #102a43;
        line-height: 1.1;
        word-break: break-word;
    }
    .metric-helper {
        margin-top: 0.35rem;
        color: #5b6b7a;
        font-size: 0.92rem;
    }
    .badge-low { color: #146c43; font-weight: 800; }
    .badge-medium { color: #b26a00; font-weight: 800; }
    .badge-high { color: #b42318; font-weight: 800; }
    .badge-neutral { color: #334155; font-weight: 800; }
    .card {
        padding: 1rem 1.05rem;
        border-radius: 0.95rem;
        background: rgba(255, 255, 255, 0.88);
        border: 1px solid rgba(17, 32, 51, 0.08);
        box-shadow: 0 10px 22px rgba(18, 32, 51, 0.05);
    }
    .label {
        font-size: 0.82rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #5b6b7a;
        margin-bottom: 0.35rem;
    }
    .ai-section {
        padding: 1rem;
        border-radius: 1rem;
        background: linear-gradient(135deg, rgba(15, 118, 110, 0.08), rgba(16, 42, 67, 0.06));
        border: 1px solid rgba(15, 118, 110, 0.18);
        box-shadow: 0 10px 22px rgba(18, 32, 51, 0.05);
        margin-top: 0.25rem;
    }
    .ai-title {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 1.05rem;
        font-weight: 800;
        color: #102a43;
        margin-bottom: 0.75rem;
    }
    .ai-pill {
        display: inline-flex;
        align-items: center;
        padding: 0.22rem 0.6rem;
        border-radius: 999px;
        background: rgba(15, 118, 110, 0.12);
        color: #0f766e;
        font-size: 0.74rem;
        font-weight: 800;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    f"""
    <div class="hero">
        <h1>{APP_TITLE}</h1>
        <p>Paste an email to get a clear threat verdict, the strongest red flags, and a safe next action.</p>
        <div class="hero-badges">
            <span class="hero-badge">Fast triage</span>
            <span class="hero-badge">Clear explanations</span>
            <span class="hero-badge">Actionable signals</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.session_state.setdefault("email_text", "")
st.session_state.setdefault("analysis_result", None)
st.session_state.setdefault("selected_sample", "Phishing raw email")
st.session_state.setdefault("sample_message", "")
st.session_state.setdefault("ai_explanation_cache_signature", "")
st.session_state.setdefault("ai_explanation_cache_result", None)

with st.sidebar:
    st.markdown("### System Overview")
    st.write(
        "PhishLens combines language cues, header authentication checks, URL/domain heuristics, and attachment metadata into one score. It never sends email, fetches remote links, or calls a paid API."
    )
    st.info("Decision-support prototype, not a perfect verdict engine.")

    mode_label = st.selectbox("Analysis mode", ["Email body only", "Full raw email with headers"], index=1)
    selected_sample = st.selectbox(
        "Example email",
        list(SAMPLE_FILES.keys()),
        index=list(SAMPLE_FILES.keys()).index(st.session_state.get("selected_sample", "Phishing raw email")),
    )
    st.session_state["selected_sample"] = selected_sample

    if st.button("Load selected sample"):
        _load_sample(selected_sample)

    with st.expander("How it works"):
        st.markdown(
            """
            - Parse the pasted email locally.
            - Score language, headers, URLs, and attachments separately.
            - Blend the scores into one explainable risk score.
            - Show the strongest evidence in a presentation-friendly report.
            """
        )

    st.markdown("### Safety Note")
    st.caption("The app does not visit links, download files, or attempt any offensive action. It only analyzes pasted text and metadata.")
    ai_explanation_enabled = st.toggle("Enable AI explanation", value=False, key="enable_ai_explanation")
    st.caption(
        "When AI explanation is enabled, structured analysis evidence may be sent to an external AI provider. Do not submit real emails containing personal, confidential, or sensitive information unless you have permission."
    )
    if st.session_state.get("sample_message"):
        st.success(st.session_state["sample_message"])

analysis_mode = "body" if mode_label == "Email body only" else "raw"

left_col, right_col = st.columns([1.45, 0.85], gap="large")

with left_col:
    st.markdown("## Input Workspace")
    st.markdown(
        """
        <div class='panel'>
            <div style='font-weight:700; margin-bottom:0.35rem;'>Paste the message below</div>
            <div style='color:#5b6b7a;'>Use raw email mode for headers, or body-only mode for copied message text.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.text_area(
        "Paste the email content here",
        key="email_text",
        height=390,
        placeholder="Paste a full raw email or just the body text here...",
        label_visibility="collapsed",
    )
    analyze_clicked = st.button("Analyze Email", type="primary", use_container_width=True)
    st.caption("Tip: Load a sample from the sidebar to instantly see phishing vs legitimate examples.")

with right_col:
    st.markdown("## Quick Overview")
    st.markdown(
        """
        <div class='card'>
            <div class='label'>What you get</div>
            <div style='font-size:1.02rem; font-weight:700; margin-bottom:0.35rem;'>A triage-style report, not a blunt yes/no answer.</div>
            <div style='color:#5b6b7a;'>The interface surfaces the score, the top red flags, the parsed sender details, and a safe action recommendation.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("<div style='height:0.65rem;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class='card'>
            <div class='label'>Current focus</div>
            <div style='font-size:1.02rem; font-weight:700; margin-bottom:0.35rem;'>Full-message analysis</div>
            <div style='color:#5b6b7a;'>Paste the complete email and the app will inspect sender identity, authentication results, suspicious language, and link structure together.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if analyze_clicked:
    if not st.session_state.get("email_text", "").strip():
        st.warning("Paste or load an email before running analysis.")
    else:
        with st.spinner("Analyzing email locally..."):
            st.session_state["analysis_result"] = analyze_email(st.session_state["email_text"], mode=analysis_mode)

result = st.session_state.get("analysis_result")

if result:
    risk_class = result.get("risk_level", "Low")
    risk_color = _score_color(risk_class)
    badge_class = _badge_class(risk_class)
    score_value = int(result.get("final_score", 0))
    component_scores = {
        "Linguistic": result.get("linguistic", {}).get("linguistic_risk_score", 0),
        "Headers": result.get("technical", {}).get("authentication_risk_score", 0),
        "URLs": result.get("urls", {}).get("url_risk_score", 0),
        "Attachments": result.get("attachments", {}).get("attachment_risk_score", 0),
    }
    parsed = result.get("parsed_email", {})
    url_count = len(result.get("urls", {}).get("extracted_urls", []))

    st.markdown("## Verdict")
    st.markdown(
        f"""
        <div class="score-banner">
            <div class="label">Hybrid verdict</div>
            <div class="{badge_class}" style="font-size: 1.5rem;">{risk_class.upper()} RISK</div>
            <div style="margin-top:0.35rem; font-size:1rem; color:#334155;">
                {result.get('prediction', 'Likely legitimate')} based on a weighted blend of language, header, URL, and attachment signals.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    score_col, level_col, prediction_col, url_col = st.columns(4)
    score_col.markdown(_metric_card("Risk score", f"{score_value}/100", "Weighted hybrid score", risk_color), unsafe_allow_html=True)
    level_col.markdown(_metric_card("Risk level", risk_class, "Low / Medium / High", risk_color), unsafe_allow_html=True)
    prediction_col.markdown(_metric_card("Prediction", result.get("prediction", "Likely legitimate"), "Triage recommendation", risk_color), unsafe_allow_html=True)
    url_col.markdown(_metric_card("URLs found", str(url_count), "Links extracted from body", "#0f766e"), unsafe_allow_html=True)

    st.progress(min(max(score_value, 0), 100) / 100, text="Overall phishing risk")

    _section_header("Signal Summary", "The hybrid engine splits the message into signal families so you can see what drove the verdict.")
    component_cards = st.columns(4)
    card_specs = [
        ("Linguistic", component_scores["Linguistic"], "Phrase patterns and tone"),
        ("Headers", component_scores["Headers"], "SPF / DKIM / DMARC and mismatches"),
        ("URLs", component_scores["URLs"], "Shorteners, lookalikes, and domain tricks"),
        ("Attachments", component_scores["Attachments"], "Suspicious filenames and extensions"),
    ]
    for col, (title, value, helper) in zip(component_cards, card_specs):
        col.markdown(_metric_card(title, f"{value}", helper, risk_color), unsafe_allow_html=True)

    _section_header("Sender Snapshot", "Parsed details extracted from the raw email when available.")
    snapshot_df = pd.DataFrame(
        [
            {"Field": "From", "Value": parsed.get("from", "") or "-"},
            {"Field": "Reply-To", "Value": parsed.get("reply_to", "") or "-"},
            {"Field": "Return-Path", "Value": parsed.get("return_path", "") or "-"},
            {"Field": "Message-ID", "Value": parsed.get("message_id", "") or "-"},
            {"Field": "Subject", "Value": parsed.get("subject", "") or "-"},
            {"Field": "Received count", "Value": len(parsed.get("received_headers", []) or [])},
        ]
    )
    st.dataframe(snapshot_df, use_container_width=True, hide_index=True)

    _section_header("Evidence Explorer", "Open each tab to review the strongest signals by family.")
    tab_tech, tab_lang, tab_url, tab_attach = st.tabs(["Technical", "Linguistic", "URLs & Domains", "Attachments"])

    with tab_tech:
        _evidence_table(
            "Technical evidence",
            result.get("technical", {}).get("evidence", []),
            "No technical authentication or header red flags were detected in this message.",
        )
    with tab_lang:
        _evidence_table(
            "Linguistic evidence",
            result.get("linguistic", {}).get("detected_cues", []),
            "No strong phishing-style language cues were detected.",
        )
    with tab_url:
        _evidence_table(
            "URL / domain evidence",
            result.get("urls", {}).get("evidence", []),
            "No suspicious URLs were extracted from the message body.",
        )
    with tab_attach:
        _evidence_table(
            "Attachment evidence",
            result.get("attachments", {}).get("evidence", []),
            "No suspicious attachments were present in the parsed metadata.",
        )

    action_col, expl_col = st.columns([1, 1], gap="large")
    with action_col:
        st.markdown("### Plain-English explanation")
        st.markdown(
            f"<div class='card'><div style='font-size:1.02rem; line-height:1.7;'>{result.get('plain_explanation', '')}</div></div>",
            unsafe_allow_html=True,
        )
    with expl_col:
        st.markdown("### Recommended safe action")
        st.markdown(
            f"<div class='card'><div style='font-size:1.02rem; line-height:1.7;'>{result.get('recommended_safe_action', '')}</div></div>",
            unsafe_allow_html=True,
        )

    ai_result = None
    if ai_explanation_enabled:
        if not is_ai_available():
            st.warning("AI explanation is enabled, but no GEMINI_API_KEY is configured. Showing local explanation instead.")
        else:
            ai_payload = build_sanitized_payload(result)
            ai_signature = json.dumps(ai_payload, sort_keys=True, ensure_ascii=False)
            if st.session_state.get("ai_explanation_cache_signature") != ai_signature:
                with st.spinner("Generating AI explanation layer..."):
                    st.session_state["ai_explanation_cache_result"] = generate_ai_explanation(result)
                    st.session_state["ai_explanation_cache_signature"] = ai_signature
            ai_result = st.session_state.get("ai_explanation_cache_result")

    st.markdown("<div class='ai-section'>", unsafe_allow_html=True)
    st.markdown("<div class='ai-title'><span class='ai-pill'>AI</span><span>AI Analysis</span></div>", unsafe_allow_html=True)
    if ai_explanation_enabled:
        if ai_result:
            ai_left, ai_right = st.columns(2)
            with ai_left:
                st.markdown(
                    f"<div class='card'><div class='label'>Plain-English explanation</div><div style='font-size:1.02rem; line-height:1.7;'>{ai_result.get('plain_english_explanation', '')}</div></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div class='card' style='margin-top:0.75rem;'><div class='label'>SOC summary</div><div style='font-size:1.02rem; line-height:1.7;'>{ai_result.get('soc_summary', '')}</div></div>",
                    unsafe_allow_html=True,
                )
            with ai_right:
                st.markdown(
                    f"<div class='card'><div class='label'>Investor pitch summary</div><div style='font-size:1.02rem; line-height:1.7;'>{ai_result.get('investor_pitch_summary', '')}</div></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div class='card' style='margin-top:0.75rem;'><div class='label'>Recommended safe action</div><div style='font-size:1.02rem; line-height:1.7;'>{ai_result.get('recommended_safe_action', '')}</div></div>",
                    unsafe_allow_html=True,
                )
            st.caption(ai_result.get("limitation_note", ""))
        else:
            st.markdown(
                """
                <div class='card'>
                    <div class='label'>AI response</div>
                    <div style='font-size:1.02rem; line-height:1.7;'>AI explanation is enabled, but no external AI response was generated. The app is showing the existing local explanation instead.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            """
            <div class='card'>
                <div class='label'>AI response</div>
                <div style='font-size:1.02rem; line-height:1.7;'>Enable AI explanation in the sidebar to generate an additional Gemini explanation layer on top of the rule-based result.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    strongest = result.get("top_signals", [])
    if strongest:
        st.markdown("### Strongest Signals")
        strongest_df = pd.DataFrame(
            [
                {
                    "Family": item.get("category", "signal").title(),
                    "Signal": item.get("signal") or item.get("issue") or item.get("category") or "Signal",
                    "Detail": item.get("explanation") or item.get("reason") or item.get("issue") or "",
                    "Points": item.get("points", 0),
                }
                for item in strongest
            ]
        )
        st.dataframe(strongest_df, use_container_width=True, hide_index=True)

    with st.expander("Technical summary for SOC / security audience"):
        st.write(result.get("technical_summary", ""))
        st.caption(result.get("technical", {}).get("summary_note", ""))

    with st.expander("Plain-English summary"):
        st.write(result.get("plain_english_summary", ""))

    with st.expander("Parsed email details"):
        parsed_df = pd.DataFrame(
            [
                {"Field": "From", "Value": parsed.get("from", "")},
                {"Field": "Reply-To", "Value": parsed.get("reply_to", "")},
                {"Field": "Return-Path", "Value": parsed.get("return_path", "")},
                {"Field": "Message-ID", "Value": parsed.get("message_id", "")},
                {"Field": "Subject", "Value": parsed.get("subject", "")},
                {"Field": "Received count", "Value": len(parsed.get("received_headers", []) or [])},
            ]
        )
        st.dataframe(parsed_df, use_container_width=True, hide_index=True)
else:
    st.markdown("## Results")
    st.info("Load a sample email or paste your own text, then click Analyze Email to generate the hybrid phishing triage report.")
    st.markdown(
        """
        <div class='card'>
            <div class='label'>Preview</div>
            <div style='font-size:1.02rem; font-weight:700; margin-bottom:0.35rem;'>This becomes a structured email triage report.</div>
            <div style='color:#5b6b7a;'>When you analyze a message, the app shows a score, verdict, summary cards, and evidence tables instead of a raw debug dump.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
