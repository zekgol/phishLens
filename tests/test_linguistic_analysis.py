from src.linguistic_analysis import analyze_linguistic


def test_detects_polish_urgency_and_account_request():
    result = analyze_linguistic("Prosimy potraktować to jako pilne. Natychmiast potwierdź konto i zaloguj się.")

    assert result["linguistic_risk_score"] > 0
    assert any(cue["matched_text"] == "pilne" for cue in result["detected_cues"])
    assert any(cue["matched_text"] == "natychmiast" for cue in result["detected_cues"])
