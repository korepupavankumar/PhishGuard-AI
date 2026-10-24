
from src.message_analyzer import analyze_message


def test_message_analyzer_returns_expected_structure():
    result = analyze_message("Hello, please review this message.")

    assert isinstance(result, dict)
    assert "urls" in result
    assert "indicators" in result


def test_extracts_https_url():
    message = "Visit https://example.com/login to review your account."
    result = analyze_message(message)

    assert any(
        "https://example.com/login" in url
        for url in result["urls"]
    )


def test_detects_urgent_language():
    result = analyze_message(
        "URGENT: Act immediately to verify your account."
    )

    assert len(result["indicators"]) > 0


def test_detects_password_request():
    result = analyze_message(
        "Please verify your password immediately."
    )

    assert len(result["indicators"]) > 0


def test_message_without_url_returns_empty_url_list():
    result = analyze_message(
        "Hello, this is a normal message with no link."
    )

    assert result["urls"] == []


def test_empty_message_does_not_crash():
    result = analyze_message("")

    assert isinstance(result, dict)
    assert "urls" in result
    assert "indicators" in result
