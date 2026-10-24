
import os
import requests


def _local_explanation(url_result=None, message_result=None) -> str:
    """Generate a basic explanation from observed evidence."""
    points = []

    if url_result:
        status = url_result.get("status")

        if status == "success":
            points.append(
                f"URL model prediction: {url_result.get('prediction', 'Unknown')}."
            )

            score = url_result.get("phishing_score")
            if score is not None:
                points.append(
                    f"Model-estimated phishing probability: {score:.1%}."
                )

            features = url_result.get("features", {})
            if features.get("has_ip_address"):
                points.append("The URL hostname is an IP address.")

            if features.get("at_symbol_count", 0) > 0:
                points.append("The URL contains an @ symbol.")

            if features.get("suspicious_keyword_count", 0) > 0:
                points.append(
                    "The URL contains terms commonly associated with "
                    "account or verification activity."
                )

        else:
            points.append(
                f"URL analysis status: {status or 'unavailable'}."
            )

    if message_result:
        indicators = message_result.get("indicators", [])

        for indicator in indicators:
            points.append(
                f"{indicator.get('type', 'Indicator')}: "
                f"{', '.join(indicator.get('evidence', []))}."
            )

        if not indicators:
            points.append(
                "No configured message warning signs were detected."
            )

    if not points:
        points.append(
            "No analysis evidence was provided. Submit a URL or message."
        )

    points.append(
        "This is a preliminary assessment. URL patterns and message "
        "keywords alone cannot prove that content is malicious or safe."
    )

    return "\n".join(f"- {point}" for point in points)


def generate_explanation(
    url_result=None,
    message_result=None,
) -> str:
    """Use Gemini when configured; otherwise explain locally."""
    fallback = _local_explanation(url_result, message_result)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        return fallback

    evidence = {
        "url_analysis": url_result or {},
        "message_analysis": message_result or {},
    }

    prompt = (
        "Explain this phishing investigation for a student cybersecurity "
        "project. Use only the supplied evidence. Do not invent facts, "
        "claim that a website was visited, or guarantee safety. Clearly "
        "distinguish model estimates from confirmed facts. Recommend "
        "cautious next steps. Evidence:\n"
        f"{evidence}"
    )

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.5-flash:generateContent"
    )

    try:
        response = requests.post(
            endpoint,
            params={"key": api_key},
            json={
                "contents": [
                    {"parts": [{"text": prompt}]}
                ]
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "\n".join(
                part.get("text", "")
                for part in parts
                if part.get("text")
            ).strip()

            if text:
                return text

    except (requests.RequestException, ValueError, KeyError):
        pass

    return fallback
