from password_checker import (
    calculate_entropy,
    has_sequence,
    has_keyboard_pattern,
    analyze_password,
    get_rating,
    estimate_crack_time,
)


def test_entropy_increases_with_complexity():
    weak_password = "password"
    strong_password = "G7!kP2@zQ9Lm4#Xr"

    weak_entropy = calculate_entropy(weak_password)
    strong_entropy = calculate_entropy(strong_password)

    assert strong_entropy > weak_entropy


def test_sequence_detection():
    assert has_sequence("abc") is True
    assert has_sequence("123") is True
    assert has_sequence("321") is True


def test_sequence_detection_negative():
    assert has_sequence("x7Q") is False


def test_keyboard_pattern_detection():
    assert has_keyboard_pattern("qwerty") is True
    assert has_keyboard_pattern("asdfgh") is True
    assert has_keyboard_pattern("zxcvbn") is True


def test_keyboard_pattern_negative():
    assert has_keyboard_pattern("G7!kP2@zQ9Lm") is False


def test_common_password_is_penalized():
    result = analyze_password("password")

    assert result["score"] < 50


def test_strong_password_gets_higher_score():
    weak = analyze_password("password")
    strong = analyze_password("G7!kP2@zQ9Lm4#Xr")

    assert strong["score"] > weak["score"]


def test_rating_levels():
    assert get_rating(10) == "Very Weak"
    assert get_rating(40) == "Weak"
    assert get_rating(60) == "Fair"
    assert get_rating(80) == "Strong"
    assert get_rating(95) == "Very Strong"


def test_crack_time_returns_text():
    result = estimate_crack_time(
        "G7!kP2@zQ9Lm4#Xr"
    )

    assert isinstance(result, str)
    assert len(result) > 0