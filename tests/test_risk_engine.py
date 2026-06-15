from src.risk_engine import analyze_email, combine_risk_scores


def test_combine_risk_scores_uses_expected_weights():
    assert combine_risk_scores(100, 100, 100, 100) == 100
    assert combine_risk_scores(100, 50, 0, 0) == 55


def test_full_analysis_returns_complete_result():
    result = analyze_email(
        "Final warning: verify your account immediately at https://bit.ly/example-update",
        mode="body",
    )

    assert "final_score" in result
    assert "risk_level" in result
    assert "prediction" in result
    assert isinstance(result.get("top_signals", []), list)
