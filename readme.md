# 🛡️ PhishGuard AI
### Intelligent Phishing Investigation and Prevention Assistant

PhishGuard AI is a machine-learning-based cybersecurity assistant designed to help users investigate suspicious URLs and potentially malicious messages. It combines URL feature extraction, phishing classification, message analysis, evidence-based explanations, investigation history, and PDF reporting in a Streamlit application.

> **Disclaimer:** PhishGuard AI provides preliminary analysis for educational and cybersecurity-awareness purposes. Its predictions are not a guarantee that a URL or message is safe or malicious.

## Features

- **URL phishing detection:** Classifies submitted URLs using a trained machine-learning pipeline.
- **URL feature extraction:** Examines URL characteristics such as length, hostname structure, HTTPS usage, IP addresses, digits, and suspicious keywords.
- **Message analysis:** Extracts URLs and identifies configured warning indicators, including urgency, credential requests, and payment-related language.
- **AI-assisted explanations:** Generates an evidence-based explanation using local analysis, with optional Gemini API integration.
- **Investigation history:** Saves previous investigations locally in JSON format.
- **PDF reports:** Generates downloadable investigation reports.
- **Streamlit dashboard:** Provides a simple interface for submitting URLs and messages and reviewing results.
- **Automated tests:** Includes tests for URL features, message analysis, and model predictions.

## Technology Stack

- Python
- Streamlit
- Pandas and NumPy
- Scikit-learn
- Joblib
- ReportLab
- Python-dotenv
- Google Gemini API (optional)
- Pytest

## Project Structure

```text
PhishGuard_AI/
├── app.py
├── train_model.py
├── inspect_dataset.py
├── requirements.txt
├── readme.md
├── .env.example
├── data/
│   └── PhiUSIIL_Phishing_URL_Dataset.csv
├── models/
│   └── phishing_model.joblib
├── reports/
│   ├── metrics.json
│   ├── classification_report.json
│   └── confusion_matrix.png
├── src/
│   ├── __init__.py
│   ├── url_features.py
│   ├── ml_engine.py
│   ├── message_analyzer.py
│   ├── ai_explainer.py
│   ├── history.py
│   └── reporting.py
└── tests/
    ├── test_url_features.py
    ├── test_message_analyzer.py
    └── test_ml_engine.py
```

## Installation

### 1. Clone or download the repository

Open a terminal in the project directory.

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Prepare the dataset

Place `PhiUSIIL_Phishing_URL_Dataset.csv` in the `data/` directory.

Inspect the dataset:

```bash
python inspect_dataset.py
```

### 4. Train the model

```bash
python train_model.py
```

The training script saves the model and evaluation reports in the `models/` and `reports/` directories.

If a trained model is already present, you can proceed directly to the dashboard.

### 5. Configure the optional Gemini API

Copy `.env.example` to `.env` and add your own Gemini API key if you want to enable API-based explanations.

```text
GEMINI_API_KEY=your_api_key_here
```

Keep `.env` private. Never