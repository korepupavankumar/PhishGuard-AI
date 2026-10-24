
from src.url_features import (
    FEATURE_NAMES,
    extract_url_features,
    normalize_url,
)


def test_feature_names_are_defined():
    assert len(FEATURE_NAMES) == 12
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_extract_url_features_returns_expected_features():
    url = "https://example.com/login?user=test"
    features = extract_url_features(url)

    assert isinstance(features, dict)
    assert set(features.keys()) == set(FEATURE_NAMES)


def test_https_url_is_detected():
    features = extract_url_features("https://example.com")

    assert features["uses_https"] == 1


def test_http_url_is_not_marked_as_https():
    features = extract_url_features("http://example.com")

    assert features["uses_https"] == 0


def test_url_with_ip_address_is_detected():
    features = extract_url_features("http://192.168.1.1/login")

    assert features["has_ip_address"] == 1


def test_url_with_suspicious_keyword_is_detected():
    features = extract_url_features(
        "https://example.com/verify-account"
    )

    assert features["suspicious_keyword_count"] > 0


def test_normalize_url_adds_scheme_when_missing():
    normalized = normalize_url("example.com/login")

    assert normalized.startswith("http://") or normalized.startswith("https://")


def test_normalize_url_preserves_https():
    normalized = normalize_url("https://example.com/login")

    assert normalized.startswith("https://")
