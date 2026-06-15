# PhishLens: Hybrid AI Phishing Triage Assistant

PhishLens is an offline, explainable Streamlit prototype for phishing triage. It analyzes pasted email content locally using rule-based signals from language, headers, URLs, and attachment metadata, then combines them into one transparent risk score.

## Problem Statement

People miss phishing messages because attackers mix urgency, legitimate-looking sender details, deceptive URLs, and attachment tricks. This is even harder across languages and institutional contexts. PhishLens demonstrates a practical, decision-support workflow that helps users inspect suspicious email before they click, reply, or download.

## Features

- Body-only and raw-email analysis modes
- Local parsing of email headers with Python's built-in `email` package
- Linguistic phishing cue detection in English and Polish
- SPF, DKIM, DMARC, Reply-To, Return-Path, and Message-ID analysis
- URL and domain heuristics, including shortened links and lookalikes
- Attachment filename risk analysis
- Explainable hybrid scoring with plain-English output
- Presentation-ready Streamlit UI for a live pitch demo
- Offline operation with no API keys and no database

## Architecture

```text
User pastes email
        |
        v
Streamlit UI (app.py)
        |
        +--> email_parser.py
        |       - body text
        |       - headers
        |       - attachment metadata
        |
        +--> linguistic_analysis.py
        |       - urgency / credential / fear cues
        |
        +--> technical_analysis.py
        |       - SPF / DKIM / DMARC
        |       - header mismatches
        |
        +--> url_analysis.py
        |       - shortened links
        |       - lookalikes
        |       - brand/domain heuristics
        |
        +--> attachment_analysis.py
        |       - risky extensions
        |       - double extensions
        |
        +--> risk_engine.py
                - weighted fusion
                - final score and class
                - explanation_generator.py
                        - plain-English explanation
                        - safe action guidance
```

## How to Run Locally

```bash
git clone <repo-url>
cd phishlens
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt
streamlit run app.py
```

## Streamlit Community Cloud Deployment

1. Push this repository to GitHub.
2. Sign in to Streamlit Community Cloud.
3. Create a new app and connect the GitHub repository.
4. Set the main file path to `app.py`.
5. Deploy.

No secrets or external services are required. The app runs entirely from local Python code and the bundled sample emails.

## Optional Gemini AI Explanation Layer

The core PhishLens score stays local and rule-based. Gemini is only used to generate an optional explanation layer on top of the existing analysis result.

### Local setup on Windows PowerShell

```powershell
$env:GEMINI_API_KEY="your_api_key_here"
streamlit run app.py
```

### Local setup on macOS/Linux

```bash
export GEMINI_API_KEY="your_api_key_here"
streamlit run app.py
```

### Streamlit Cloud setup

Add this to Streamlit secrets:

```toml
GEMINI_API_KEY="your_api_key_here"
```

### Notes

- The app works without Gemini.
- Gemini is only used for explanation generation.
- The rule-based engine remains the source of the risk score.
- Avoid submitting sensitive real emails to external AI providers unless you have permission.

## Example Use Cases

- University security awareness demos
- SOC triage walkthroughs
- AI R&D pitch presentations
- Security training for non-technical staff
- Comparative demos for English and Polish phishing language

## Safety Note

PhishLens is defensive and educational. It does not send email, crawl targets, fetch remote URLs, or perform offensive actions. It only analyzes text and metadata that a user pastes into the app.

## Limitations

- Rule-based detection can miss novel phishing tactics.
- A legitimate email can still look suspicious, especially when sender domains or wording are unusual.
- Authentication signals are helpful, but compromised legitimate accounts can still pass SPF, DKIM, or DMARC.
- URL analysis is string-based only; the app does not visit or validate links.

## Future Improvements

- Add more multilingual phrase sets
- Add brand-specific domain policy profiles
- Add optional browser-extension workflow
- Add dataset import for evaluation and calibration
- Add explanation templates tailored to user role

## Course Pitch Angle

This project is designed for an end-of-course Shark Tank-style AI R&D demo. It shows a realistic cybersecurity workflow, a clear architecture, explainable scoring, and measurable next steps without relying on paid APIs or hidden model behavior.

## Project Structure

```text
phishlens/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── sample_emails/
│   ├── phishing_raw_email.txt
│   ├── legitimate_raw_email.txt
│   ├── phishing_body_only.txt
│   └── legitimate_body_only.txt
├── src/
│   ├── __init__.py
│   ├── email_parser.py
│   ├── linguistic_analysis.py
│   ├── technical_analysis.py
│   ├── url_analysis.py
│   ├── attachment_analysis.py
│   ├── risk_engine.py
│   └── explanation_generator.py
└── tests/
    ├── test_linguistic_analysis.py
    ├── test_url_analysis.py
    └── test_risk_engine.py
```
