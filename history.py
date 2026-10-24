
import json
import os
from datetime import datetime, timezone
from pathlib import Path

HISTORY_PATH = Path(
    os.getenv("HISTORY_PATH", "reports/investigation_history.json")
)


def load_history() -> list:
    """Load previously saved investigations."""
    if not HISTORY_PATH.exists():
        return []

    try:
        content = HISTORY_PATH.read_text(encoding="utf-8").strip()
        if not content:
            return []

        data = json.loads(content)
        return data if isinstance(data, list) else []

    except (OSError, json.JSONDecodeError):
        return []


def save_investigation(
    url: str = "",
    prediction: str = "",
    phishing_score=None,
    message_indicator_count: int = 0,
    message: str = "",
) -> dict:
    """Save one investigation while preserving existing history."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "prediction": prediction,
        "phishing_score": phishing_score,
        "message_indicator_count": int(message_indicator_count),
        "message": message[:1000],
    }

    history = load_history()
    history.insert(0, record)

    # Keep the latest 500 investigations.
    history = history[:500]

    temp_path = HISTORY_PATH.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temp_path.replace(HISTORY_PATH)

    return record


def clear_history() -> None:
    """Clear saved investigation history."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text("[]", encoding="utf-8")
