from src.url_analysis import analyze_urls


def test_detects_shortened_url():
    result = analyze_urls("Click here: https://bit.ly/example-update")

    assert result["url_risk_score"] > 0
    assert any(item["issue"] == "Shortened URL" for item in result["evidence"])


def test_detects_lookalike_domain():
    result = analyze_urls("Please review https://micros0ft.com/security")

    assert any(item["issue"] == "Lookalike domain" for item in result["evidence"])
