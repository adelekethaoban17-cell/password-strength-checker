import hashlib
import math
import pathlib
import string
import urllib.error
import urllib.request


def load_common_passwords(filepath: str = "10k-passwords.txt") -> set[str]:
    path = pathlib.Path(filepath)
    if not path.is_file():
        return {
            "123456", "password", "123456789", "qwerty", "12345678",
            "111111", "1234567890", "abc123", "password1", "admin"
        }

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return {line.strip().lower() for line in file if line.strip()}


COMMON_PASSWORDS = load_common_passwords()


def check_hibp_pwned(password: str) -> int:
    if not password:
        return 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "PasswordStrengthChecker-Lib"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                return 0

            hashes = response.read().decode("utf-8").splitlines()
            for line in hashes:
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return int(count)

    except (urllib.error.URLError, TimeoutError):
        return 0

    return 0


def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    if any(c not in (string.ascii_letters + string.digits + string.punctuation) for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def get_rating(score: int) -> str:
    if score < 20:
        return "Very Weak"
    elif score < 40:
        return "Weak"
    elif score < 60:
        return "Fair"
    elif score < 80:
        return "Strong"
    else:
        return "Very Strong"


def analyze_password(password: str) -> dict:
    feedback = []
    raw_entropy = calculate_entropy(password)

    base_score = min(100.0, (raw_entropy / 100.0) * 100.0)
    score_cap = 100.0

    if len(password) < 8:
        feedback.append("Password is too short. Use at least 12 characters.")
    elif len(password) < 12:
        feedback.append("Consider increasing length to 12+ characters for better security.")

    if not any(c.islower() for c in password):
        feedback.append("Add lowercase letters.")
    if not any(c.isupper() for c in password):
        feedback.append("Add uppercase letters.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add numbers.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add special characters.")

    if password.lower() in COMMON_PASSWORDS:
        score_cap = min(score_cap, 0.0)
        feedback.append("CRITICAL: Password matches a known breached/common password.")

    breach_count = check_hibp_pwned(password)
    if breach_count > 0:
        score_cap = min(score_cap, 0.0)
        feedback.append(
            f"CRITICAL: Found in live data breaches ({breach_count:,} times according to HaveIBeenPwned)."
        )

    final_score = int(round(min(base_score, score_cap)))

    return {
        "score": final_score,
        "rating": get_rating(final_score),
        "entropy_bits": round(raw_entropy, 2),
        "breach_count": breach_count,
        "is_pwned": breach_count > 0,
        "feedback": feedback
    }


if __name__ == "__main__":
    test_pwd = "P@ssword123!"
    result = analyze_password(test_pwd)
    print("Sample Output:")
    print(result)
