# Password Strength & Breach Analyzer

A lightweight, zero-dependency Python utility designed for seamless integration into web applications, authentication backend workflows, and user registration pipelines.

It provides structured password strength evaluation combining **Shannon Entropy calculation**, **O(1) local top-10k common password matching**, and **k-Anonymity breach lookup** via the HaveIBeenPwned API.

## Key Features

- **Zero Third-Party Dependencies:** Implemented using Python standard library modules (`hashlib`, `math`, `pathlib`, `urllib`).
- **Data Breach Detection:** Queries HaveIBeenPwned k-Anonymity API without exposing password plaintexts or complete hashes.
- **Offline High-Risk Protection:** Instant O(1) set matching against the 10,000 most common passwords.
- **Developer-Friendly API:** Returns structured Python dictionaries ready for serialization into JSON or integration into web frameworks like Flask, Django, or FastAPI.

## Usage Guide for Developers

### 1. Basic Integration

Import the `analyze_password` function into your user registration or authentication handler:

```python
from password_checker import analyze_password

# Example user password input
user_input = "P@ssword2026!"

# Analyze strength
result = analyze_password(user_input)

if result["is_pwned"]:
    print("Registration Blocked: Password found in public breaches.")
    print("Feedback:", result["feedback"])
else:
    print(f"Password Rating: {result['rating']} (Score: {result['score']}/100)")