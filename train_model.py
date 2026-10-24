
from pathlib import Path
import json
import time

import joblib
import matplotlib.pyplot as plt
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from src.url_features import extract_url_features, FEATURE_NAMES

DATASET_PATH = Path("data/PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_PATH = Path("models/phishing_model.joblib")
REPORTS_DIR = Path("reports")


def main():
    start = time.time()

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH.resolve()}"
        )

    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH, usecols=["URL", "label"])

    df = df.dropna(subset=["URL", "label"])
    df["URL"] = df["URL"].astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df = df[df["label"].isin([0, 1])]

    # If duplicate URLs have conflicting labels, exclude those URLs.
    label_counts = df.groupby("URL")["label"].nunique()
    conflicting_urls = label_counts[label_counts > 1].index
    df = df[~df["URL"].isin(conflicting_urls)]
    df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

    if len(df) < 10:
        raise ValueError("Not enough valid dataset records to train.")

    # Dataset label 0 = phishing, 1 = legitimate.
    # Model target 1 = phishing, 0 = legitimate.
    y = (df["label"] == 0).astype(int)

    print(f"Usable unique URLs: {len(df):,}")
    print("Extracting URL features...")

    feature_rows = []
    valid_indices = []

    for index, url in enumerate(df["URL"]):
        try:
            features = extract_url_features(url)
            feature_rows.append(features)
            valid_indices.append(index)
        except (ValueError, TypeError):
            continue

        if (index + 1) % 25000 == 0:
            print(f"Processed {index + 1:,} records...")

    if not feature_rows:
        raise ValueError("No valid URL features could be extracted.")

    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = y.iloc[valid_indices].reset_index(drop=True)

    print(f"Valid records: {len(X):,}")
    print("Splitting training and testing data...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        )),
    ])

    print("Training Logistic Regression model...")
    model.fit(X_train, y_train)

    print("Evaluating model...")
    predictions = model.predict(X_test)

    metrics = {
        "model": "Logistic Regression",
        "dataset": str(DATASET_PATH),
        "features": FEATURE_NAMES,
        "total_valid_records": int(len(X)),
        "training_records": int(len(X_train)),
        "testing_records": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "phishing_precision": float(
            precision_score(y_test, predictions, zero_division=0)
        ),
        "phishing_recall": float(
            recall_score(y_test, predictions, zero_division=0)
        ),
        "phishing_f1_score": float(
            f1_score(y_test, predictions, zero_division=0)
        ),
        "target_mapping": {
            "0": "legitimate",
            "1": "phishing",
        },
        "evaluation_note": (
            "Random stratified split; URL-level duplicates removed. "
            "This is a baseline, not a guarantee of real-world performance."
        ),
    }

    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        output_dict=True,
        zero_division=0,
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    with open(REPORTS_DIR / "metrics.json", "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    with open(
        REPORTS_DIR / "classification_report.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(report, file, indent=4)

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])

    plt.figure(figsize=(6, 5))
    plt.imshow(matrix)
    plt.title("PhishGuard AI - Confusion Matrix")
    plt.xlabel("Predicted label")
    plt.ylabel("Actual label")
    plt.xticks([0, 1], ["Legitimate", "Phishing"])
    plt.yticks([0, 1], ["Legitimate", "Phishing"])

    for row in range(2):
        for col in range(2):
            plt.text(
                col,
                row,
                str(matrix[row, col]),
                ha="center",
                va="center",
            )

    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    print("\n--- Model Evaluation ---")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['phishing_precision']:.4f}")
    print(f"Recall:    {metrics['phishing_recall']:.4f}")
    print(f"F1-score:  {metrics['phishing_f1_score']:.4f}")

    print("\n--- Classification Report ---")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    ))

    print(f"Model saved to: {MODEL_PATH}")
    print(f"Reports saved to: {REPORTS_DIR.resolve()}")
    print(f"Elapsed time: {time.time() - start:.1f} seconds")


if __name__ == "__main__":
    main()
