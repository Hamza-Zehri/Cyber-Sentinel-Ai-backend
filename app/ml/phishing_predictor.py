"""
Cyber Sentinel AI - Phishing URL predictor.
Loads the trained RandomForest model and produces a label (safe/suspicious/
phishing), risk score, confidence, and a human-readable explanation listing
the specific red flags detected in the URL.
"""
from pathlib import Path
from typing import Optional

import joblib

from app.ml.feature_extraction import extract_features, features_to_vector

MODEL_PATH = Path(__file__).resolve().parents[2] / "ai_models" / "phishing_url_model.joblib"

_cached_model = None
_cached_feature_names = None


def _load_model():
    global _cached_model, _cached_feature_names
    if _cached_model is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(
                "Phishing model not found. Run `python -m app.ml.train_phishing_model` first."
            )
        bundle = joblib.load(MODEL_PATH)
        _cached_model = bundle["model"]
        _cached_feature_names = bundle["feature_names"]
    return _cached_model, _cached_feature_names


def _build_reasons(features: dict) -> list:
    reasons = []
    if features["has_ip_address"]:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if features["is_shortened"]:
        reasons.append("URL uses a known link-shortening service, which can hide the true destination")
    if features["has_at_symbol"]:
        reasons.append("URL contains an '@' symbol, often used to obscure the real destination")
    if features["suspicious_keyword_count"] >= 2:
        reasons.append(f"URL contains {features['suspicious_keyword_count']} suspicious keywords "
                        "(e.g. 'login', 'verify', 'secure', 'confirm')")
    if features["num_hyphens"] >= 3:
        reasons.append("Domain/path contains an unusually high number of hyphens, common in brand-lookalike domains")
    if features["num_subdomains"] >= 3:
        reasons.append("URL has an unusually high number of subdomains")
    if features["domain_entropy"] >= 3.8:
        reasons.append("Domain name has high character randomness (possible auto-generated phishing domain)")
    if not features["has_https"]:
        reasons.append("URL does not use HTTPS")
    if features["digit_letter_ratio"] > 0.3:
        reasons.append("Domain contains an unusually high ratio of digits to letters")
    if not reasons:
        reasons.append("No major structural red flags detected")
    return reasons


def predict_url(url: str) -> dict:
    model, feature_names = _load_model()
    features = extract_features(url)
    vector = [features_to_vector(features)]

    proba = model.predict_proba(vector)[0]
    phishing_proba = float(proba[1])

    if phishing_proba >= 0.70:
        label = "phishing"
    elif phishing_proba >= 0.35:
        label = "suspicious"
    else:
        label = "safe"

    confidence = float(max(proba))
    reasons = _build_reasons(features)

    explanation = (
        f"This URL was classified as '{label}' with a phishing risk score of "
        f"{phishing_proba * 100:.1f}%. " + " ".join(reasons[:3]) + "."
    )

    return {
        "url": url,
        "label": label,
        "risk_score": round(phishing_proba * 100, 2),
        "confidence": round(confidence * 100, 2),
        "reasons": reasons,
        "explanation": explanation,
        "features": features,
    }
