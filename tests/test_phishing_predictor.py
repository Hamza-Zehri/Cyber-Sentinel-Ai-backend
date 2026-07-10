from app.ml.phishing_predictor import predict_url


def test_known_safe_domain_classified_safe():
    result = predict_url("https://github.com/anthropics/claude")
    assert result["label"] == "safe"
    assert result["risk_score"] < 35


def test_ip_address_host_classified_phishing():
    result = predict_url("http://192.168.45.2/login/verify-account")
    assert result["label"] == "phishing"
    assert any("IP address" in r for r in result["reasons"])


def test_brand_lookalike_classified_high_risk():
    result = predict_url("http://paypal-secure-login-verify.tk/confirm.php")
    assert result["label"] in ("phishing", "suspicious")
    assert result["risk_score"] > 50


def test_url_shortener_flagged_as_reason():
    result = predict_url("https://bit.ly/3xR9zAa")
    assert any("link-shortening" in r for r in result["reasons"])


def test_response_contains_required_fields():
    result = predict_url("https://example.com")
    for key in ("url", "label", "risk_score", "confidence", "reasons", "explanation"):
        assert key in result
    assert 0 <= result["risk_score"] <= 100
    assert 0 <= result["confidence"] <= 100
