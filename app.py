from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from src.risk_engine import analyze_email


APP_TITLE = "PhishLens: Hybrid AI Phishing Triage Assistant"
ROOT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT_DIR / "sample_emails"
SAMPLE_FILES = {
    "Phishing raw email": SAMPLES_DIR / "phishing_raw_email.txt",
    "Legitimate raw email": SAMPLES_DIR / "legitimate_raw_email.txt",
    "Phishing body only": SAMPLES_DIR / "phishing_body_only.txt",
    "Legitimate body only": SAMPLES_DIR / "legitimate_body_only.txt",
}


st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(180deg, #f6f8fb 0%, #eef2f7 100%);
        color: #122033;
    }
    .hero {
        padding: 1.2rem 1.4rem;
        border-radius: 1rem;
        background: linear-gradient(135deg, #102a43 0%, #1f4f67 55%, #2f6f6f 100%);
        color: white;
        border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 12px 30px rgba(16, 42, 67, 0.18);
    }
    .hero h1 {
        margin-bottom: 0.3rem;
    }
    .hero p {
        margin: 0.3rem 0 0 0;
        opacity: 0.95;
        font-size: 1.02rem;
    }
    .card {
        padding: 1rem 1.1rem;
        border-radius: 0.9rem;
        background: rgba(255, 255, 255, 0.82);
        border: 1px solid rgba(17, 32, 51, 0.08);
        box-shadow: 0 10px 22px rgba(18, 32, 51, 0.06);
    }
    .label {
        font-size: 0.82rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #5b6b7a;
        margin-bottom: 0.35rem;
    }
    .risk-low { color: #146c43; font-weight: 700; }
    .risk-medium { color: #b26a00; font-weight: 700; }
    .risk-high { color: #b42318; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    f"""
    <div class="hero">
        <h1>{APP_TITLE}</h1>
        <p>Offline, explainable email triage for phishing awareness, SOC demoing, and university pitch presentations. Paste an email, inspect the signals, and see why the model thinks the message is safe or suspicious.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.session_state.setdefault("email_text", "")
st.session_state.setdefault("analysis_result", None)
st.session_state.setdefault("selected_sample", "Phishing raw email")

with st.sidebar:
    st.markdown("### System Overview")
    st.write(
        "PhishLens combines language cues, header authentication checks, URL/domain heuristics, and attachment metadata into a single risk score. It never sends email, fetches remote links, or calls a paid API."
    )
    st.info("This is a decision-support prototype, not a perfect verdict engine.")

    mode_label = st.selectbox("Analysis mode", ["Email body only", "Full raw email with headers"], index=1)
    selected_sample = st.selectbox("Example email", list(SAMPLE_FILES.keys()), index=list(SAMPLE_FILES.keys()).index(st.session_state.get("selected_sample", "Phishing raw email")))
    st.session_state["selected_sample"] = selected_sample
    if st.button("Load selected sample"):
        sample_path = SAMPLE_FILES.get(selected_sample)
        if sample_path and sample_path.exists():
            st.session_state["email_text"] = sample_path.read_text(encoding="utf-8")
            st.session_state["analysis_result"] = None
        else:
            st.error("Sample file not found.")

    with st.expander("How it works"):
        st.markdown(
            """
            - Parse the pasted email locally.
            - Score language, headers, URLs, and attachments separately.
            - Blend the scores into one explainable risk score.
            - Show the strongest evidence in plain English.
            """
        )

    st.markdown("### Safety Note")
    st.caption("The app does not visit links, download files, or attempt any offensive action. It only analyzes text and metadata that the user pastes into the box.")

analysis_mode = "body" if mode_label == "Email body only" else "raw"

st.markdown("## Email to analyze")
st.text_area(
    "Paste the email content here",
    key="email_text",
    height=320,
    placeholder="Paste a full raw email or just the body text here...",
    label_visibility="collapsed",
)

button_col, helper_col = st.columns([1, 3])
with button_col:
    analyze_clicked = st.button("Analyze Email", type="primary", use_container_width=True)
with helper_col:
    st.caption("Tip: Load one of the examples from the sidebar to see how the hybrid signals change across phishing and legitimate messages.")

if analyze_clicked:
    if not st.session_state.get("email_text", "").strip():
        st.warning("Paste or load an email before running analysis.")
    else:
        with st.spinner("Analyzing email locally..."):
            st.session_state["analysis_result"] = analyze_email(st.session_state["email_text"], mode=analysis_mode)

result = st.session_state.get("analysis_result")

if result:
    risk_class = result.get("risk_level", "Low")
    risk_class_slug = risk_class.lower()
    component_scores = {
        "Linguistic": result.get("linguistic", {}).get("linguistic_risk_score", 0),
        "Headers": result.get("technical", {}).get("authentication_risk_score", 0),
        "URLs": result.get("urls", {}).get("url_risk_score", 0),
        "Attachments": result.get("attachments", {}).get("attachment_risk_score", 0),
    }

    st.markdown("## Results")
    score_col, level_col, prediction_col, urls_col = st.columns(4)
    score_col.metric("Final risk score", f"{result.get('final_score', 0)}/100")
    level_col.metric("Final risk level", risk_class)
    prediction_col.metric("Prediction", result.get("prediction", "Likely legitimate"))
    urls_col.metric("URLs found", len(result.get("urls", {}).get("extracted_urls", [])))

    st.markdown(
        f"<div class='card'><div class='label'>Hybrid summary</div><div class='risk-{risk_class_slug}'>This message is classified as {risk_class.upper()} risk.</div><div style='margin-top:0.4rem;'>The score combines linguistic, technical, URL, and attachment evidence using a weighted rule-based model.</div></div>",
        unsafe_allow_html=True,
    )

    st.markdown("### Component Scores")
    component_df = pd.DataFrame(
        [{"Signal family": key, "Score": value} for key, value in component_scores.items()]
    )
    st.dataframe(component_df, use_container_width=True, hide_index=True)

    def render_evidence_table(title: str, rows: list[dict], empty_message: str) -> None:
        st.subheader(title)
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info(empty_message)

    technical_rows = result.get("technical", {}).get("evidence", [])
    linguistic_rows = result.get("linguistic", {}).get("detected_cues", [])
    url_rows = result.get("urls", {}).get("evidence", [])
    attachment_rows = result.get("attachments", {}).get("evidence", [])

    render_evidence_table(
        "Technical evidence",
        technical_rows,
        "No technical authentication or header red flags were detected in this message.",
    )
    render_evidence_table(
        "Linguistic evidence",
        linguistic_rows,
        "No strong phishing-style language cues were detected.",
    )
    render_evidence_table(
        "URL / domain evidence",
        url_rows,
        "No suspicious URLs were extracted from the message body.",
    )
    render_evidence_table(
        "Attachment evidence",
        attachment_rows,
        "No suspicious attachments were present in the parsed metadata.",
    )

    st.subheader("Plain-English explanation")
    st.markdown(result.get("plain_explanation", ""))

    st.subheader("Recommended safe action")
    st.markdown(result.get("recommended_safe_action", ""))

    with st.expander("Technical summary for SOC / security audience"):
        st.write(result.get("technical_summary", ""))
        st.caption(result.get("technical", {}).get("summary_note", ""))

    with st.expander("Investor-friendly summary"):
        st.write(result.get("investor_summary", ""))

    with st.expander("Plain-English summary"):
        st.write(result.get("plain_english_summary", ""))

    with st.expander("Parsed email details"):
        parsed = result.get("parsed_email", {})
        fields_df = pd.DataFrame(
            [
                {"Field": "From", "Value": parsed.get("from", "")},
                {"Field": "Reply-To", "Value": parsed.get("reply_to", "")},
                {"Field": "Return-Path", "Value": parsed.get("return_path", "")},
                {"Field": "Message-ID", "Value": parsed.get("message_id", "")},
                {"Field": "Subject", "Value": parsed.get("subject", "")},
                {"Field": "Received count", "Value": len(parsed.get("received_headers", []) or [])},
            ]
        )
        st.dataframe(fields_df, use_container_width=True, hide_index=True)

    with st.expander("How the explanation was generated"):
        strongest = result.get("top_signals", [])
        if strongest:
            st.markdown(
                "\n".join(
                    f"- {item.get('category', 'signal').title()}: {item.get('explanation') or item.get('reason') or item.get('issue')}"
                    for item in strongest
                )
            )
        else:
            st.write("No strong signals were available for explanation.")

    with st.expander("Shark Tank Pitch View"):
        st.markdown(
            """
            **Problem:**
            People struggle to detect phishing, especially across languages and institutional contexts.

            **Architecture:**
            Hybrid rule-based prototype combining linguistic features, email authentication signals, URL analysis, attachment metadata, and explainable risk scoring.

            **Data:**
            Synthetic labelled emails can be collected in English and Polish, labelled by phishing/legitimate status, tone, language, and suspicious cues.

            **Fairness:**
            Evaluate performance separately by language, tone, and user group. Avoid English-only phishing bias.

            **Success metrics:**
            Precision, recall, false negative rate, explanation usefulness, and reduction in unsafe clicks in user testing.

            **Shipping:**
            Deploy as a web app, browser extension, or SOC triage assistant. Monitor user feedback and false positives.

            **ROI:**
            Reduce phishing risk, improve security awareness, and support faster email triage.
            """
        )

    with st.expander("Pitch summary"):
        st.markdown(
            """
            - **Problem:** Traditional users miss phishing because language, sender identity, and URL tricks vary by campaign and language.
            - **Architecture:** Local, explainable, offline triage engine with four signal families and weighted fusion.
            - **Data:** Synthetic labeled English and Polish emails support course demos without using live attack data.
            - **Fairness:** Measure language-specific false negatives and avoid bias toward English-only cues.
            - **Success metrics:** Precision, recall, explanation usefulness, and reduced risky clicks.
            - **Shipping:** Streamlit demo today; browser extension or SOC queue helper later.
            - **ROI:** Lower phishing exposure and faster human review.
            """
        )
else:
    st.markdown("## Results")
    st.info("Load a sample email or paste your own text, then click Analyze Email to generate the hybrid phishing triage report.")

