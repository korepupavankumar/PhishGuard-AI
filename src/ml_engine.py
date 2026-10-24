
import os
from pathlib import Path

import joblib
import pandas as pd

from src.url_features import extract_url_features, FEATURE_NAMES


MODEL_PATH = Path(
    os.getenv("MODEL_PATH", "models/phishing_model.joblib")
)


def load_model():
    """Load the trained phishing detection model."""
    if not MODEL_PATH.exists():
        return None

    try:
        return joblib.load(MODEL_PATH)
    except (OSError, ValueError, EOFError):
        return None


def predict_url(url: str) -> dict:
    """
    Predict whether a URL may be phishing.

    Internal model labels:
        0 = legitimate
        1 = phishing
    """
    try:
        features = extract_url_features(url)
    except (ValueError, TypeError) as exc:
        return {
            "status": "invalid_url",
            "url": url,
            "prediction": "Invalid URL",
            "phishing_score": None,
            "features": {},
            "message": str(exc),
        }

    model = load_model()

    if model is None:
        return {
            "status": "model_unavailable",
            "url": url,
            "prediction": "Model not trained",
            "phishing_score": None,
            "features": features,
            "message": "Train the model before making predictions.",
        }

    try:
        # Explicit column ordering keeps inference consistent with training.
        X = pd.DataFrame([features], columns=FEATURE_NAMES)
        predicted_label = int(model.predict(X)[0])

        phishing_score = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X)[0]
            classes = list(model.classes_)

            if 1 in classes:
                phishing_score = float(probabilities[classes.index(1)])

        is_phishing = predicted_label == 1

        return {
            "status": "success",
            "url": url,
            "prediction": (
                "Potential phishing"
                if is_phishing
                else "Potentially legitimate"
            ),
            "is_phishing": is_phishing,
            "phishing_score": phishing_score,
            "features": features,
            "message": (
                "This is a model estimate, not a guarantee. "
                "Verify suspicious links independently."
            ),
        }

    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        return {
            "status": "prediction_error",
            "url": url,
            "prediction": "Prediction unavailable",
            "phishing_score": None,
            "features": features,
            "message": f"Could not make prediction: {exc}",
        }
