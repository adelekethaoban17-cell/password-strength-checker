import getpass
import hashlib
import math
import pathlib
import string
import urllib.error
import urllib.request


# ---------------------------------------------------------
# LOAD COMMON PASSWORDS
# ---------------------------------------------------------

def load_common_passwords(
    filepath: str = "10k-passwords.txt"
) -> set[str]:
    """Load common passwords from a local file."""

    path = pathlib.Path(filepath)

    if not path.is_file():
        return {
            "123456",
            "password",
            "123456789",
            "qwerty",
            "12345678",
            "111111",
            "1234567890",
            "abc123",
            "password1",
            "admin",
        }

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return {line.strip().casefold() for line in file if line.strip()}


COMMON_PASSWORDS = load_common_passwords()


# ---------------------------------------------------------
# ENTROPY CALCULATION
# ---------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """
    Calculate theoretical maximum entropy in bits.

    This assumes every character was selected randomly from the
    detected character pool. Human-created passwords usually have
    much less effective entropy because attackers exploit patterns,
    dictionaries, reuse, and predictable substitutions.
    """

    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26

    if any(char.isupper() for char in password):
        pool_size += 26

    if any(char.isdigit() for char in password):
        pool_size += 10

    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


# ---------------------------------------------------------
# SEQUENCE DETECTION
# ---------------------------------------------------------

def has_sequence(password: str, sequence_length: int = 3) -> bool:
    """Detect ascending or descending ASCII character sequences."""

    if sequence_length < 2:
        return False

    password = password.casefold()

    for i in range(len(password) - sequence_length + 1):
        chunk = password[i:i + sequence_length]

        ascending = all(
            ord(chunk[j]) + 1 == ord(chunk[j + 1])
            for j in range(len(chunk) - 1)
        )

        descending = all(
            ord(chunk[j]) - 1 == ord(chunk[j + 1])
            for j in range(len(chunk) - 1)
        )

        if ascending or descending:
            return True

    return False


# ---------------------------------------------------------
# KEYBOARD PATTERN DETECTION
# ---------------------------------------------------------

def has_keyboard_pattern(password: str) -> bool:
    """Detect common keyboard-row patterns in a password."""

    password = password.casefold()

    keyboard_patterns = [
        "qwerty", "ytrewq", "qwertyuiop", "poiuytrewq",
        "asdf", "fdsa", "asdfgh", "hgfdsa", "asdfghjkl", "lkjhgfdsa",
        "zxcv", "vcxz", "zxcvbn", "nbvcxz", "zxcvbnm", "mnbvcxz",
        "123456", "654321", "1234567890", "0987654321",
        "qaz", "zaq", "wsx", "xsw", "edc", "cde",
    ]

    return any(pattern in password for pattern in keyboard_patterns)


# ---------------------------------------------------------
# REPETITION DETECTION
# ---------------------------------------------------------

def has_repetition(password: str) -> bool:
    """Detect obvious repeated characters or short repeated chunks."""

    if len(password) < 3:
        return False

    # Examples: aaa, 1111, !!!!
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True

    # Examples: abab, 1212, !@!@
    for size in (2, 3):
        for i in range(len(password) - (size * 2) + 1):
            chunk = password[i:i + size]
            if chunk == password[i + size:i + (size * 2)]:
                return True

    return False


# ---------------------------------------------------------
# CRACK-TIME ESTIMATION
# ---------------------------------------------------------

def estimate_crack_time(
    password: str,
    guesses_per_second: int = 10_000_000_000,
) -> str:
    """
    Estimate theoretical offline brute-force crack time.

    The default guessing speed is only a scenario assumption. Real
    cracking speed depends heavily on the password hash algorithm,
    hardware, attack strategy, and whether the attack is online or
    offline. This estimate should not be treated as a guarantee.
    """

    if guesses_per_second <= 0:
        raise ValueError("guesses_per_second must be greater than zero")

    entropy = calculate_entropy(password)
    possible_guesses = 2 ** entropy
    seconds = possible_guesses / (2 * guesses_per_second)

    if seconds < 1:
        return "Less than a second"

    if seconds < 60:
        return f"{seconds:.1f} seconds"

    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"

    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"

    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"

    years = days / 365
    if years < 1_000:
        return f"{years:.1f} years"

    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"

    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"

    return f"{years / 1_000_000_000:.1f} billion years"


# ---------------------------------------------------------
# HAVE I BEEN PWNED CHECK
# ---------------------------------------------------------

def check_hibp_pwned(password: str) -> int:
    """
    Check whether a password appears in known breaches.

    Uses the Have I Been Pwned k-anonymity API. Only the first five
    characters of the SHA-1 hash are sent to the API; the full hash
    is never transmitted.

    Returns:
        Positive integer: number of breach occurrences.
        0: password hash was not found.
        -1: the check could not be completed.
    """

    if not password:
        return 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "PasswordStrengthChecker"},
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = response.read().decode("utf-8", errors="ignore")

        for line in data.splitlines():
            if ":" not in line:
                continue

            returned_suffix, count = line.split(":", 1)

            if returned_suffix.strip().upper() == suffix:
                try:
                    return int(count.strip())
                except ValueError:
                    return -1

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ):
        return -1

    return 0


# ---------------------------------------------------------
# PASSWORD ANALYSIS
# ---------------------------------------------------------

def analyze_password(password: str) -> dict:
    """Analyze password complexity and return a score from 0 to 100."""

    score = 0
    feedback = []
    length = len(password)

    # Password length
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
        feedback.append("Use at least 12 characters.")
    else:
        score += 5
        feedback.append("Password is too short. Use at least 12 characters.")

    # Character variety
    if any(char.islower() for char in password):
        score += 10
    else:
        feedback.append("Add lowercase letters.")

    if any(char.isupper() for char in password):
        score += 10
    else:
        feedback.append("Add uppercase letters.")

    if any(char.isdigit() for char in password):
        score += 10
    else:
        feedback.append("Add numbers.")

    if any(char in string.punctuation for char in password):
        score += 15
    else:
        feedback.append("Add special characters.")

    # Common-password detection
    if password.casefold() in COMMON_PASSWORDS:
        score -= 40
        feedback.append("This password appears in the common-password database.")

    # Repetition detection
    if has_repetition(password):
        score -= 10
        feedback.append("Avoid obvious repeated characters or repeated patterns.")

    # Predictable sequences
    if has_sequence(password):
        score -= 10
        feedback.append("Avoid predictable sequences such as abc or 123.")

    # Keyboard patterns
    if has_keyboard_pattern(password):
        score -= 10
        feedback.append("Avoid common keyboard patterns such as qwerty or asdf.")

    score = max(0, min(score, 100))
    entropy = calculate_entropy(password)

    return {
        "score": score,
        "entropy_bits": round(entropy, 2),
        "feedback": feedback,
    }


# ---------------------------------------------------------
# PASSWORD RATING
# ---------------------------------------------------------

def get_rating(score: int) -> str:
    """Convert a numerical complexity score into a rating."""

    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Fair"
    elif score < 90:
        return "Strong"
    else:
        return "Very Strong"


# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------

def main():
    print("=" * 55)
    print("             PASSWORD STRENGTH CHECKER")
    print("=" * 55)
    print("\nYour password will not be displayed or stored by this program.")

    password = getpass.getpass("\nEnter password: ")

    if not password:
        print("\nPassword cannot be empty.")
        return

    result = analyze_password(password)
    score = result["score"]
    entropy = result["entropy_bits"]
    feedback = result["feedback"]
    crack_time = estimate_crack_time(password)

    print("\nChecking known data breaches...")
    breach_count = check_hibp_pwned(password)

    rating = get_rating(score)

    print("\n" + "=" * 55)
    print("                     RESULTS")
    print("=" * 55)
    print(f"Complexity score:     {score}/100")
    print(f"Complexity rating:    {rating}")
    print(f"Theoretical entropy:  {entropy} bits")
    print(f"Estimated crack time: {crack_time}")

    if breach_count == -1:
        print("Breach count:          Unable to check")
        print("Security status:       CHECK FAILED")
        feedback.append(
            "Breach check could not be completed. Check your internet connection."
        )
    elif breach_count > 0:
        print(f"Breach count:          {breach_count:,}")
        print("Security status:       COMPROMISED")
        print("Final recommendation:  DO NOT USE THIS PASSWORD")
        feedback.append(
            "CRITICAL: This password has appeared in known data breaches. Do not use it."
        )
    else:
        print("Breach count:          0")
        print("Security status:       NOT FOUND IN HIBP")

    if feedback:
        print("\nHow to improve:")
        for item in feedback:
            print(f"- {item}")
    else:
        print("\nNo major weaknesses detected.")

    print("\nNote: A password not found in HIBP is not guaranteed to be safe.")
    print("=" * 55)


# ---------------------------------------------------------
# PROGRAM ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    main()
