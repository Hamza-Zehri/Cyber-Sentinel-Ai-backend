"""
Cyber Sentinel AI - Phishing URL model training.

Trains a RandomForestClassifier on a programmatically generated, rule-labeled
dataset (safe vs. phishing URL patterns). This is disclosed clearly in the
documentation: it is a lexical/structural classifier trained on synthetic
examples of well-known phishing patterns (IP-address hosts, brand-lookalike
hyphenation, URL shorteners, suspicious keyword stuffing, high-entropy
subdomains) rather than a live threat-intel feed. It's a legitimate, testable
first line of defense — real deployments should periodically retrain it on
live-labeled traffic once available.
"""
import random
import string
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from app.ml.feature_extraction import FEATURE_NAMES, extract_features, features_to_vector

MODEL_DIR = Path(__file__).resolve().parents[2] / "ai_models"
MODEL_PATH = MODEL_DIR / "phishing_url_model.joblib"

SAFE_DOMAINS = [
    "github.com", "google.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "stackoverflow.com", "reddit.com", "nytimes.com", "bbc.co.uk",
    "linkedin.com", "spotify.com", "netflix.com", "dropbox.com", "notion.so",
    "cloudflare.com", "python.org", "mozilla.org", "wordpress.com", "shopify.com",
]
SAFE_PATHS = ["", "/docs", "/about", "/products/item123", "/blog/post-title",
              "/search?q=test", "/user/settings", "/api/v1/resource", "/login",
              "/help/faq", "/pricing", "/contact"]

BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix", "bankofamerica", "chase", "wellsfargo"]
SUSPICIOUS_TLDS = ["ru", "tk", "top", "xyz", "click", "info", "gq"]


def _random_string(n: int, charset=string.ascii_lowercase + string.digits) -> str:
    return "".join(random.choice(charset) for _ in range(n))


def _gen_safe_url() -> str:
    domain = random.choice(SAFE_DOMAINS)
    path = random.choice(SAFE_PATHS)
    scheme = "https"
    return f"{scheme}://{domain}{path}"


def _gen_phishing_url() -> str:
    pattern = random.choice(["ip_host", "brand_lookalike", "shortener", "keyword_stuffed", "random_subdomain"])

    if pattern == "ip_host":
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        path = "/" + random.choice(["login", "verify", "secure-update", "account/confirm"])
        return f"http://{ip}{path}"

    if pattern == "brand_lookalike":
        brand = random.choice(BRANDS)
        fake = f"{brand}-{_random_string(5)}-verify-account"
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{fake}.{tld}/login.php?confirm=1"

    if pattern == "shortener":
        shortener = random.choice(["bit.ly", "tinyurl.com", "goo.gl", "cutt.ly"])
        return f"http://{shortener}/{_random_string(7)}"

    if pattern == "keyword_stuffed":
        brand = random.choice(BRANDS)
        kws = random.sample(["login", "verify", "secure", "account", "update", "confirm", "suspend"], 3)
        subdomain = "-".join(kws)
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{subdomain}.{brand}-{_random_string(4)}.{tld}/{'-'.join(kws)}"

    # random_subdomain: high entropy nonsense subdomain
    sub = _random_string(random.randint(10, 18), charset=string.ascii_lowercase + string.digits)
    tld = random.choice(SUSPICIOUS_TLDS)
    return f"http://{sub}.{_random_string(6)}.{tld}/wp-includes/secure"


def generate_dataset(n_per_class: int = 1500):
    rows, labels = [], []
    for _ in range(n_per_class):
        rows.append(features_to_vector(extract_features(_gen_safe_url())))
        labels.append(0)  # 0 = safe
    for _ in range(n_per_class):
        rows.append(features_to_vector(extract_features(_gen_phishing_url())))
        labels.append(1)  # 1 = phishing
    return np.array(rows), np.array(labels)


def train_and_save() -> dict:
    random.seed(42)
    np.random.seed(42)

    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["safe", "phishing"])

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_PATH)

    return {"accuracy": acc, "report": report, "model_path": str(MODEL_PATH)}


if __name__ == "__main__":
    result = train_and_save()
    print(f"Model saved to {result['model_path']}")
    print(f"Test accuracy: {result['accuracy']:.4f}")
    print(result["report"])
