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

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:
        return {
            line.strip().lower()
            for line in file
            if line.strip()
        }


COMMON_PASSWORDS = load_common_passwords()


# ---------------------------------------------------------
# ENTROPY CALCULATION
# ---------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits."""

    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26

    if any(char.isupper() for char in password):
        pool_size += 26

    if any(char.isdigit() for char in password):
        pool_size += 10

    if any(
        char in string.punctuation
        for char in password
    ):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


# ---------------------------------------------------------
# SEQUENCE DETECTION
# ---------------------------------------------------------

def has_sequence(
    password: str,
    sequence_length: int = 3
) -> bool:
    """Detect ascending or descending character sequences."""

    password = password.lower()

    for i in range(
        len(password) - sequence_length + 1
    ):
        chunk = password[
            i:i + sequence_length
        ]

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
    """Detect common keyboard patterns."""

    password = password.lower()

    keyboard_patterns = [
        "qwerty",
        "qwertyuiop",
        "asdf",
        "asdfgh",
        "asdfghjkl",
        "zxcv",
        "zxcvbn",
        "zxcvbnm",
        "123456",
        "654321",
    ]

    for pattern in keyboard_patterns:
        if pattern in password:
            return True

    return False


# ---------------------------------------------------------
# CRACK-TIME ESTIMATION
# ---------------------------------------------------------

def estimate_crack_time(password: str) -> str:
    """
    Estimate approximate offline brute-force crack time.

    This is a theoretical estimate and does not represent
    every real-world password cracking scenario.
    """

    entropy = calculate_entropy(password)

    # Assumed offline guessing speed.
    guesses_per_second = 10_000_000_000

    # Approximate number of guesses in the search space.
    possible_guesses = 2 ** entropy

    # Average successful guess occurs halfway through
    # the theoretical search space.
    seconds = possible_guesses / (
        2 * guesses_per_second
    )

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

    Uses the Have I Been Pwned k-anonymity API.
    Only the first five characters of the SHA-1 hash
    are sent to the API.
    """

    if not password:
        return 0

    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = (
        "https://api.pwnedpasswords.com/range/"
        f"{prefix}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PasswordStrengthChecker"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            data = response.read().decode(
                "utf-8",
                errors="ignore"
            )

        for line in data.splitlines():

            if ":" not in line:
                continue

            returned_suffix, count = line.split(
                ":",
                1
            )

            if returned_suffix.strip() == suffix:
                return int(count.strip())

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError
    ):
        return -1

    return 0


# ---------------------------------------------------------
# PASSWORD ANALYSIS
# ---------------------------------------------------------

def analyze_password(password: str) -> dict:
    """Analyze password security characteristics."""

    score = 0
    feedback = []

    # Password length
    length = len(password)

    if length >= 16:
        score += 30

    elif length >= 12:
        score += 25

    elif length >= 8:
        score += 15
        feedback.append(
            "Use at least 12 characters."
        )

    else:
        score += 5
        feedback.append(
            "Password is too short. "
            "Use at least 12 characters."
        )

    # Lowercase letters
    if any(char.islower() for char in password):
        score += 10
    else:
        feedback.append(
            "Add lowercase letters."
        )

    # Uppercase letters
    if any(char.isupper() for char in password):
        score += 10
    else:
        feedback.append(
            "Add uppercase letters."
        )

    # Numbers
    if any(char.isdigit() for char in password):
        score += 10
    else:
        feedback.append(
            "Add numbers."
        )

    # Special characters
    if any(
        char in string.punctuation
        for char in password
    ):
        score += 15
    else:
        feedback.append(
            "Add special characters."
        )

    # Common-password detection
    if password.lower() in COMMON_PASSWORDS:

        score -= 40

        feedback.append(
            "This password appears in the "
            "common-password database."
        )

    # Repeated characters
    if password:

        unique_characters = len(
            set(password)
        )

        if unique_characters < len(password) * 0.6:

            score -= 10

            feedback.append(
                "Avoid excessive character repetition."
            )

    # Predictable sequences
    if has_sequence(password):

        score -= 10

        feedback.append(
            "Avoid predictable sequences "
            "such as abc or 123."
        )

    # Keyboard patterns
    if has_keyboard_pattern(password):

        score -= 10

        feedback.append(
            "Avoid common keyboard patterns "
            "such as qwerty or asdf."
        )

    # Keep score between 0 and 100
    score = max(
        0,
        min(score, 100)
    )

    entropy = calculate_entropy(password)

    return {
        "score": score,
        "entropy_bits": round(
            entropy,
            2
        ),
        "feedback": feedback,
    }


# ---------------------------------------------------------
# PASSWORD RATING
# ---------------------------------------------------------

def get_rating(score: int) -> str:

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

    print(
        "\nYour password will not be displayed "
        "or stored by this program."
    )

    password = getpass.getpass(
        "\nEnter password: "
    )

    if not password:

        print(
            "\nPassword cannot be empty."
        )

        return

    # Analyze password
    result = analyze_password(password)

    score = result["score"]
    entropy = result["entropy_bits"]
    feedback = result["feedback"]

    # Estimate crack time
    crack_time = estimate_crack_time(password)

    # Check known breaches
    print(
        "\nChecking known data breaches..."
    )

    breach_count = check_hibp_pwned(
        password
    )

    # Get rating
    rating = get_rating(score)

    # -----------------------------------------------------
    # RESULTS
    # -----------------------------------------------------

    print("\n" + "=" * 55)
    print("                     RESULTS")
    print("=" * 55)

    print(
        f"Score:                 {score}/100"
    )

    print(
        f"Rating:                {rating}"
    )

    print(
        f"Estimated entropy:     {entropy} bits"
    )

    print(
        f"Estimated crack time:  {crack_time}"
    )

    # -----------------------------------------------------
    # BREACH RESULT
    # -----------------------------------------------------

    if breach_count == -1:

        print(
            "Breach count:          Unable to check"
        )

        print(
            "Status:                CHECK FAILED"
        )

        feedback.append(
            "Breach check could not be completed. "
            "Check your internet connection."
        )

    elif breach_count > 0:

        print(
            f"Breach count:          {breach_count:,}"
        )

        print(
            "Status:                COMPROMISED"
        )

        feedback.append(
            "CRITICAL: This password has appeared "
            "in known data breaches. Do not use it."
        )

    else:

        print(
            "Breach count:          0"
        )

        print(
            "Status:                Not found in HIBP"
        )

    # -----------------------------------------------------
    # FEEDBACK
    # -----------------------------------------------------

    if feedback:

        print(
            "\nHow to improve:"
        )

        for item in feedback:

            print(
                f"- {item}"
            )

    else:

        print(
            "\nNo major weaknesses detected."
        )

    print("\n" + "=" * 55)


# ---------------------------------------------------------
# PROGRAM ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":
    main()