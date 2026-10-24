
import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
)

URGENT_TERMS = [
    "urgent", "immediately", "act now", "account suspended",
    "expires today", "within 24 hours", "verify now",
]

CREDENTIAL_TERMS = [
    "password", "login", "sign in", "verification code",
    "otp", "one-time password", "bank details",
]

PAYMENT_TERMS = [
    "payment required", "pay now", "wire transfer",
    "gift card", "crypto payment", "confirm your payment",
]


def extract_urls(message: str) -> list:
    """Extract likely URLs from message text."""
    if not isinstance(message, str) or not message.strip():
        return []

    found = []
    for match in URL_PATTERN.findall(message):
        # Remove common punctuation surrounding the URL.
        candidate = match.rstrip(".,;:!?)]}")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate

        try:
            parsed = urlparse(candidate)
            if parsed.hostname and "." in parsed.hostname:
                found.append(candidate)
        except ValueError:
            continue

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(found))


def _find_terms(message: str, terms: list) -> list:
    text = message.lower()
    return [term for term in terms if term in text]


def analyze_message(message: str) -> dict:
    """Identify warning signs without claiming certainty."""
    if not isinstance(message, str) or not message.strip():
        return {
            "status": "empty_message",
            "urls": [],
            "indicators": [],
            "indicator_count": 0,
            "summary": "Enter a message to analyze.",
            "limitations": (
                "Keyword matches are warning signs, not proof of phishing."
            ),
        }

    urls = extract_urls(message)

    indicators = []

    urgent = _find_terms(message, URGENT_TERMS)
    credentials = _find_terms(message, CREDENTIAL_TERMS)
    payments = _find_terms(message, PAYMENT_TERMS)

    if urgent:
        indicators.append({
            "type": "Urgency or pressure",
            "evidence": urgent,
            "severity": "medium",
        })

    if credentials:
        indicators.append({
            "type": "Credential or sensitive-information request",
            "evidence": credentials,
            "severity": "high",
        })

    if payments:
        indicators.append({
            "type": "Payment-related language",
            "evidence": payments,
            "severity": "medium",
        })

    if urls:
        indicators.append({
            "type": "Contains link(s)",
            "evidence": urls,
            "severity": "review",
        })

    return {
        "status": "success",
        "urls": urls,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "summary": (
            "Potential warning signs found. Review the evidence."
            if indicators
            else "No configured warning signs detected. "
                 "This does not prove the message is safe."
        ),
        "limitations": (
            "This is a basic rule-based analysis. It does not verify "
            "the sender, visit links, or establish whether a message "
            "is genuinely malicious."
        ),
    }
