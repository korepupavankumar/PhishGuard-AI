
from pathlib import Path

import pytest

from src.ml_engine import predict_url


MODEL_PATH = Path("models/phishing_model.joblib")


@pytest.mark.skipif(
    not MODEL_PATH.exists(),
    reason="Train the model first using python train_model.py",
)
def test_model_returns_prediction_for_https_url():
    result = predict_url("https://example.com")

    assert result["status"] == "success"
    assert result["prediction"] in [
        "Potential phishing",
        "Potentially legitimate",
    ]
    assert isinstance(result["is_phishing"], bool)
    assert isinstance(result["phishing_score"], float)
    assert 0.0 <= result["phishing_score"] <= 1.0


@pytest.mark.skipif(
    not MODEL_PATH.exists(),
    reason="Train the model first using python train_model.py",
)
def test_model_returns_features():
    result = predict_url("https://example.com/login")

    assert result["status"] == "success"
    assert isinstance(result["features"], dict)
    assert len(result["features"]) > 0
