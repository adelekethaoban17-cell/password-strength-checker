from unittest.mock import patch
import urllib.error

from password_checker import (
    analyze_password,
    calculate_entropy,
    check_hibp_pwned,
    estimate_crack_time,
    get_rating,
    has_keyboard_pattern,
    has_repetition,
    has_sequence,
)


class FakeResponse:
    """Minimal context-manager response for HIBP tests."""

    def __init__(self, data: str):
        self.data = data.encode("utf-8")

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_entropy_increases_with_complexity():
    weak_password = "password"
    strong_password = "G7!kP2@zQ9Lm4#Xr"

    assert calculate_entropy(strong_password) > calculate_entropy(weak_password)


def test_empty_password_has_zero_entropy():
    assert calculate_entropy("") == 0.0


def test_sequence_detection():
    assert has_sequence("abc") is True
    assert has_sequence("123") is True
    assert has_sequence("321") is True
    assert has_sequence("xyz") is True
    assert has_sequence("cba") is True


def test_sequence_detection_negative():
    assert has_sequence("x7Q") is False
    assert has_sequence("a1b") is False


def test_keyboard_pattern_detection():
    assert has_keyboard_pattern("qwerty") is True
    assert has_keyboard_pattern("asdfgh") is True
    assert has_keyboard_pattern("zxcvbn") is True
    assert has_keyboard_pattern("0987654321") is True


def test_keyboard_pattern_negative():
    assert has_keyboard_pattern("G7!kP2@zQ9Lm") is False


def test_repetition_detection():
    assert has_repetition("aaa") is True
    assert has_repetition("1111") is True
    assert has_repetition("abab") is True
    assert has_repetition("1212") is True


def test_repetition_detection_negative():
    assert has_repetition("G7!kP2@zQ9Lm") is False


def test_common_password_is_penalized():
    result = analyze_password("password")

    assert result["score"] < 50
    assert any("common-password" in item for item in result["feedback"])


def test_strong_password_gets_higher_score():
    weak = analyze_password("password")
    strong = analyze_password("G7!kP2@zQ9Lm4#Xr")

    assert strong["score"] > weak["score"]


def test_predictable_patterns_are_penalized():
    result = analyze_password("Aaa123!!!")

    assert result["score"] < 70
    assert any("repeated" in item.lower() for item in result["feedback"])
    assert any("sequence" in item.lower() for item in result["feedback"])


def test_rating_levels():
    assert get_rating(10) == "Very Weak"
    assert get_rating(40) == "Weak"
    assert get_rating(60) == "Fair"
    assert get_rating(80) == "Strong"
    assert get_rating(95) == "Very Strong"


def test_rating_boundaries():
    assert get_rating(29) == "Very Weak"
    assert get_rating(30) == "Weak"
    assert get_rating(49) == "Weak"
    assert get_rating(50) == "Fair"
    assert get_rating(69) == "Fair"
    assert get_rating(70) == "Strong"
    assert get_rating(89) == "Strong"
    assert get_rating(90) == "Very Strong"


def test_crack_time_returns_text():
    result = estimate_crack_time("G7!kP2@zQ9Lm4#Xr")

    assert isinstance(result, str)
    assert len(result) > 0


def test_crack_time_rejects_invalid_speed():
    try:
        estimate_crack_time("password", guesses_per_second=0)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_hibp_detects_compromised_password():
    password = "password"
    # SHA-1(password), suffix after the first five characters.
    suffix = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    fake_response = FakeResponse(f"{suffix}:12345\n")

    with patch(
        "password_checker.urllib.request.urlopen",
        return_value=fake_response,
    ):
        assert check_hibp_pwned(password) == 12345


def test_hibp_returns_zero_when_not_found():
    with patch(
        "password_checker.urllib.request.urlopen",
        return_value=FakeResponse("ABCDEF1234567890:10\n"),
    ):
        assert check_hibp_pwned("password") == 0


def test_hibp_returns_minus_one_on_network_failure():
    with patch(
        "password_checker.urllib.request.urlopen",
        side_effect=urllib.error.URLError("network unavailable"),
    ):
        assert check_hibp_pwned("password") == -1


def test_hibp_empty_password_is_not_sent_to_api():
    with patch("password_checker.urllib.request.urlopen") as mock_urlopen:
        assert check_hibp_pwned("") == 0
        mock_urlopen.assert_not_called()
