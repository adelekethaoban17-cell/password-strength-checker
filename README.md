#

Password Strength Checker

A lightweight Python command-line tool for evaluating password strength using password composition rules and estimated entropy.

## Features

* Checks password length
* Detects lowercase letters
* Detects uppercase letters
* Detects numbers
* Detects special characters
* Calculates a password strength score
* Classifies passwords as **Weak**, **Medium**, or **Strong**
* Estimates password entropy in bits
* Uses only Python's standard library
* Includes automated tests with `pytest`

## Requirements

* Python 3.8 or newer
* pytest for running the test suite

## Installation

Clone the repository:

```bash
git clone git@github.com:adelekethaoban17-cell/password-strength-checker.git
```

Enter the project directory:

```bash
cd password-strength-checker
```

## Usage

Run the password checker:

```bash
python3 password_checker.py
```

You will be prompted to enter a password:

```text
Enter a password: MySecurePassword2026!@#

Password strength: Strong
Score: 6/6
Estimated entropy: 88.73 bits
```

## Password Strength Rules

The program awards points for the following characteristics:

| Requirement                 | Points |
| --------------------------- | -----: |
| At least 8 characters       |      1 |
| At least 12 characters      |      1 |
| Contains lowercase letters  |      1 |
| Contains uppercase letters  |      1 |
| Contains numbers            |      1 |
| Contains special characters |      1 |

### Strength levels

| Score | Strength |
| ----: | -------- |
|   0–2 | Weak     |
|   3–4 | Medium   |
|   5–6 | Strong   |

## Entropy

The program also estimates password entropy based on:

* Password length
* Lowercase characters
* Uppercase characters
* Numbers
* Special characters

The entropy result is displayed in **bits**.

Higher entropy generally indicates a larger potential password search space.

## Testing

The project includes automated tests using `pytest`.

Run the tests from the project root:

```bash
python3 -m pytest
```

Expected result:

```text
9 passed
```

## Project Structure

```text
password-strength-checker/
├── password_checker.py
├── tests/
│   └── test_password_checker.py
└── README.md
```

## Example

```text
Enter a password: password

Password strength: Weak
Score: 2/6
Estimated entropy: 37.6 bits
```

A more complex password:

```text
Enter a password: MySecurePassword2026!@#

Password strength: Strong
Score: 6/6
Estimated entropy: ...
```

## Security Note

This tool is intended for educational purposes and provides a basic heuristic assessment of password strength. Entropy is an estimate and should not be treated as a guarantee that a password is secure against every type of attack.

## License

This project is open source and available for educational use.
