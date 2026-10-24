from urllib.parse import urlparse
from ipaddress import ip_address


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "signin",
    "banking",
    "confirm",
    "wallet",
]


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "dot_count",
    "subdomain_count",
    "uses_https",
    "has_ip_address",
    "at_symbol_count",
    "hyphen_count",
    "digit_count",
    "query_length",
    "path_length",
    "suspicious_keyword_count",
]


def normalize_url(url: str) -> str:
    """Validate and normalize a URL without visiting it."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must not be empty.")

    url = url.strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    return url


def extract_url_features(url: str) -> dict:
    """Extract numerical features from URL text only."""

    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    try:
        ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    hostname_parts = hostname.split(".")
    subdomain_count = max(0, len(hostname_parts) - 2)

    lower_url = normalized_url.lower()

    suspicious_count = sum(
        keyword in lower_url
        for keyword in SUSPICIOUS_KEYWORDS
    )

    return {
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "dot_count": normalized_url.count("."),
        "subdomain_count": subdomain_count,
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_ip_address": has_ip,
        "at_symbol_count": normalized_url.count("@"),
        "hyphen_count": normalized_url.count("-"),
        "digit_count": sum(c.isdigit() for c in normalized_url),
        "query_length": len(query),
        "path_length": len(path),
        "suspicious_keyword_count": suspicious_count,
    }