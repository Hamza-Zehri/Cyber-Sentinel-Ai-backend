from app.ml.password_analyzer import analyze_password


def test_common_password_flagged_very_weak():
    result = analyze_password("password")
    assert result["is_common_password"] is True
    assert result["strength"] == "very weak"


def test_short_simple_password_is_weak():
    result = analyze_password("abc123")
    assert result["strength"] in ("very weak", "weak")


def test_strong_password_gets_high_rating():
    result = analyze_password("Xk9#mQ2$vL7pR4!wZ")
    assert result["strength"] in ("strong", "very strong")
    assert result["entropy_bits"] > 60


def test_sequential_pattern_detected():
    result = analyze_password("myPass1234!")
    assert result["has_sequential_pattern"] is True


def test_keyboard_pattern_detected():
    result = analyze_password("qwerty123!")
    assert result["has_keyboard_pattern"] is True


def test_repeated_characters_detected():
    result = analyze_password("aaaBBB111!!!")
    assert result["has_repeated_characters"] is True


def test_recommendations_present_for_weak_password():
    result = analyze_password("test")
    assert len(result["recommendations"]) > 0


def test_crack_time_format_is_human_readable():
    result = analyze_password("Xk9#mQ2$vL7pR4!wZ")
    assert isinstance(result["estimated_crack_time"], str)
    assert len(result["estimated_crack_time"]) > 0
