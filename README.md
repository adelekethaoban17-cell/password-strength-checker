# 🔐 Password Strength & Breach Analyzer

**Author: Adeleke Thaoban**

A Python-based cybersecurity tool that analyses password security using multiple security checks, including password complexity, common-password detection, predictable-pattern detection, entropy estimation, theoretical crack-time estimation, and breached-password detection.

🔗 **GitHub Repository:**
https://github.com/adelekethaoban17-cell/password-strength-checker

---

## 📌 About the Project

The **Password Strength & Breach Analyzer** is a cybersecurity-focused Python project developed to assess the security characteristics of passwords.

The tool goes beyond simple password validation by analysing several factors that can contribute to password compromise.

It evaluates:

* Password length
* Lowercase characters
* Uppercase characters
* Numbers
* Special characters
* Common passwords
* Repeated characters
* Sequential characters
* Keyboard patterns
* Estimated password entropy
* Theoretical offline brute-force crack time
* Exposure in known password breaches

The application then produces a security score from **0–100**, assigns a password-strength rating, provides security recommendations, and checks whether the password appears in known breach data.

---

# 🛡️ Cybersecurity Problem It Solves

Passwords remain an important part of authentication systems, but weak, predictable, reused, and previously exposed passwords can increase the risk of account compromise.

Attackers may use techniques such as:

* Brute-force attacks
* Dictionary attacks
* Password spraying
* Credential stuffing
* Credential reuse
* Previously leaked passwords
* Automated password-guessing attacks

For example:

```text
123456
password
qwerty
admin
password1
```

are highly predictable passwords.

A password can also satisfy basic complexity requirements while still being dangerous if it has already appeared in a data breach.

This project addresses the problem by combining **password-strength analysis and breached-password detection** into one Python security tool.

---

# 🎯 Project Objectives

The main objectives are to:

1. Identify weak passwords.
2. Detect common passwords.
3. Identify predictable sequences.
4. Detect common keyboard patterns.
5. Detect excessive character repetition.
6. Estimate password entropy.
7. Estimate theoretical offline brute-force time.
8. Check passwords against known breached-password data.
9. Provide actionable security recommendations.
10. Demonstrate Python programming skills in a cybersecurity context.

---

# ✨ Key Features

## 1. Password Strength Scoring

The application generates a score between:

```text
0 – 100
```

The score is converted into one of five ratings:

|  Score | Rating      |
| -----: | ----------- |
|   0–29 | Very Weak   |
|  30–49 | Weak        |
|  50–69 | Fair        |
|  70–89 | Strong      |
| 90–100 | Very Strong |

The score is based on several characteristics of the password.

---

## 2. Password Length Analysis

Password length is an important factor in password security.

The application rewards longer passwords and recommends using at least 12 characters.

For example:

```text
password
```

is significantly less desirable than a sufficiently long, unpredictable password.

---

## 3. Character Complexity

The tool checks whether the password contains:

* Lowercase letters
* Uppercase letters
* Numbers
* Special characters

For example:

```text
P@ssword2026!
```

contains multiple character types.

However, the project recognises that character complexity alone does not guarantee password security.

---

## 4. Common Password Detection

The program attempts to load:

```text
10k-passwords.txt
```

If the file is unavailable, a small built-in list of common passwords is used.

Examples include:

```text
123456
password
qwerty
admin
password1
```

If the password is found in the common-password database, the security score is reduced and a warning is generated.

---

## 5. Sequential Character Detection

The application detects predictable ascending and descending sequences.

Examples:

```text
abc
bcd
123
456
321
zyx
```

Attackers can include predictable patterns such as these in password-guessing strategies.

---

## 6. Keyboard Pattern Detection

The application detects common keyboard patterns such as:

```text
qwerty
asdf
zxcv
123456
654321
```

These patterns can make passwords easier to guess.

---

## 7. Repeated Character Detection

The program checks for excessive repetition.

Examples:

```text
aaaaaaaaaaaa
111111111111
Password111111
```

Highly repetitive passwords can have significantly lower effective security than their length suggests.

---

# 📊 Password Entropy

The application estimates password entropy in bits.

The estimated character pool is based on whether the password contains:

```text
Lowercase letters → 26 possibilities
Uppercase letters → 26 possibilities
Numbers           → 10 possibilities
Punctuation       → Python punctuation character set
```

The program uses:

```text
Entropy = Length × log₂(Character Pool)
```

Higher estimated entropy generally indicates a larger theoretical search space.

### ⚠️ Important

This is a theoretical estimate.

Human-created passwords can be considerably more predictable than the mathematical model assumes.

For example:

```text
Password123!
```

may contain several character categories but is still predictable because it follows a common human password pattern.

---

# ⏱️ Theoretical Crack-Time Estimation

The application estimates the theoretical time required for an offline brute-force search.

It currently assumes:

```text
10,000,000,000 guesses/second
```

The result may be displayed as:

```text
Less than a second
15.4 minutes
4.2 days
12.7 years
2.5 thousand years
```

### ⚠️ Important limitation

This is **not a prediction of an actual attack**.

Real-world password-cracking performance depends on:

* Password-hashing algorithm
* Hashing parameters
* Hardware
* GPUs
* Attack methodology
* Password structure
* Dictionary attacks
* Credential reuse
* Rate limiting
* Account lockout controls

The estimate is primarily intended for educational and security-awareness purposes.

---

# 🌐 Breached Password Detection

The application integrates with the **Have I Been Pwned Pwned Passwords API**.

It uses the API's **k-anonymity model**.

The process is:

```text
Password
    ↓
SHA-1 Hash
    ↓
First 5 characters of hash
    ↓
Send hash prefix to API
    ↓
Receive matching hash suffixes
    ↓
Compare locally
    ↓
Return breach count
```

The complete password is not sent to the API.

The program locally compares the returned hash suffix with the remaining portion of the password's SHA-1 hash.

---

# 🔐 Password Privacy

The program uses:

```python
getpass.getpass()
```

instead of:

```python
input()
```

This prevents the password from being displayed while it is being entered into the terminal.

The application also does not intentionally write the plaintext password to disk.

### Important

Users should still avoid entering passwords they currently use for sensitive accounts into software they do not trust.

For demonstrations, use test passwords.

---

# 🧰 Technologies Used

The project uses the Python standard library.

```text
Python 3
```

### Python modules

| Module           | Purpose                            |
| ---------------- | ---------------------------------- |
| `getpass`        | Secure terminal password input     |
| `hashlib`        | SHA-1 hashing                      |
| `math`           | Entropy calculations               |
| `pathlib`        | File and path management           |
| `string`         | Character and punctuation handling |
| `urllib.request` | HTTP/API communication             |
| `urllib.error`   | Network error handling             |

### Dependencies

The project currently has:

```text
0 third-party Python dependencies
```

This makes it lightweight and easy to run.

---

# 📁 Project Structure

```text
password-strength-checker/
│
├── .github/
│   └── workflows/
│
├── .gitignore
├── 10k-passwords.txt
├── password_checker.py
└── README.md
```

### `password_checker.py`

Contains the main Python application.

### `10k-passwords.txt`

Contains the local common-password database.

### `README.md`

Contains the project documentation.

---

# ⚙️ Requirements

You need:

* Python 3.9 or later
* Internet connection for breach checking
* Linux, macOS, or Windows

For Kali Linux:

```bash
python3 --version
```

Example:

```text
Python 3.13.x
```

---

# 📥 Installation

Clone the repository:

```bash
git clone https://github.com/adelekethaoban17-cell/password-strength-checker.git
```

Move into the project directory:

```bash
cd password-strength-checker
```

Verify Python:

```bash
python3 --version
```

No `pip install` command is required because the current version uses Python's standard library.

---

# ▶️ Usage

Run the program:

```bash
python3 password_checker.py
```

You should see:

```text
=======================================================
             PASSWORD STRENGTH CHECKER
=======================================================

Your password will not be displayed or stored by this program.

Enter password:
```

Enter a test password.

The program will then analyse the password and display the results.

---

# 📊 Example Output

```text
=======================================================
                     RESULTS
=======================================================

Score:                 25/100
Rating:                Very Weak
Estimated entropy:     56.87 bits
Estimated crack time:  Less than a second

Breach count:          123456
Status:                COMPROMISED

How to improve:
- Use at least 12 characters.
- This password appears in the common-password database.
- Avoid predictable sequences such as abc or 123.
- CRITICAL: This password has appeared in known data breaches. Do not use it.

=======================================================
```

The exact result depends on the password being analysed.

---

# 🧠 How the Program Works

The overall workflow is:

```text
              USER ENTERS PASSWORD
                       │
                       ▼
                Secure Input
                  getpass()
                       │
                       ▼
              Password Analysis
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     Length        Complexity       Patterns
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                Common Password
                    Check
                       │
                       ▼
                 Entropy Estimate
                       │
                       ▼
              Crack-Time Estimate
                       │
                       ▼
              Breach Database Check
                       │
                       ▼
                 Security Score
                       │
                       ▼
              Security Recommendations
```

---

# 🧩 Main Functions

The project is divided into reusable Python functions.

### `load_common_passwords()`

Loads the common-password database.

```python
load_common_passwords()
```

---

### `calculate_entropy()`

Estimates password entropy.

```python
calculate_entropy(password)
```

---

### `has_sequence()`

Detects ascending or descending character sequences.

```python
has_sequence(password)
```

---

### `has_keyboard_pattern()`

Detects common keyboard patterns.

```python
has_keyboard_pattern(password)
```

---

### `estimate_crack_time()`

Estimates theoretical offline brute-force time.

```python
estimate_crack_time(password)
```

---

### `check_hibp_pwned()`

Checks the password against the Pwned Passwords API using the k-anonymity approach.

```python
check_hibp_pwned(password)
```

---

### `analyze_password()`

Combines the major password-security checks and returns:

```python
{
    "score": ...,
    "entropy_bits": ...,
    "feedback": [...]
}
```

---

### `get_rating()`

Converts the numerical score into a human-readable rating.

```python
get_rating(score)
```

---

### `main()`

Controls the application's user interface and execution flow.

---

# 🛡️ Cybersecurity Applications

This project has practical relevance to several cybersecurity areas.

## 🔵 Security Awareness

Organisations can use password-security tools to educate users about:

* Weak passwords
* Password reuse
* Predictable passwords
* Breached credentials
* Strong authentication practices

---

## 🔵 Identity & Access Management

Password strength is relevant to authentication security.

Security teams can use similar concepts when developing:

* Password policies
* Account-registration controls
* Authentication systems
* Credential security standards

---

## 🔵 SOC Operations

Security Operations Centre analysts may investigate:

* Authentication failures
* Credential compromise
* Password-related incidents
* Data breaches
* Suspicious authentication activity

Python automation can help security teams process and analyse security data.

---

## 🔵 Penetration Testing

Password security assessments can be part of authorised penetration-testing engagements.

A security tester may evaluate whether an organisation's authentication controls adequately protect against weak or compromised credentials.

Testing should always be performed with appropriate authorisation.

---

## 🔵 GRC

Governance, Risk and Compliance teams can use password-security assessments to support:

* Password policies
* Security controls
* Risk assessments
* Security awareness programmes
* Compliance requirements

---

# 💼 Professional Skills Demonstrated

This project demonstrates practical knowledge of:

### Python Programming

```text
Functions
Loops
Conditional statements
Sets
Dictionaries
Type hints
Docstrings
String processing
Exception handling
```

### Cybersecurity

```text
Password security
Credential security
Brute-force concepts
Dictionary attacks
Data breaches
K-anonymity
Security scoring
Risk assessment
```

### Cryptography

```text
SHA-1 hashing
Hash comparison
Entropy
Cryptographic concepts
```

### Networking

```text
HTTP requests
HTTPS
REST-style API communication
Timeouts
HTTP errors
```

### Secure Programming

```text
Secure password input
Avoiding plaintext password storage
Error handling
Input processing
Security-aware API integration
```

---

# ⚠️ Limitations

This tool should be considered an **educational and security-awareness project**, not a complete enterprise password-security system.

## Entropy Limitation

The entropy calculation is based on character categories and does not fully model human password behaviour.

## Crack-Time Limitation

The crack-time estimate uses a fixed theoretical guessing speed and therefore cannot represent every real-world attack.

## Breach Database Limitation

A password not found in the Pwned Passwords dataset does not prove that it has never been exposed.

## Common Password Database Limitation

The quality of common-password detection depends on the contents of:

```text
10k-passwords.txt
```

## No Password Generation

The current application does not generate cryptographically secure passwords.

---

# 🚀 Future Improvements

Possible future versions could introduce:

### 1. Secure Password Generator

Use Python's:

```python
secrets
```

module to generate strong random passwords.

### 2. Improved Password Analysis

Implement more sophisticated password-strength estimation that considers:

* Dictionary words
* Names
* Dates
* Common substitutions
* Keyboard walks
* Repeated patterns
* Predictable structures

### 3. Graphical User Interface

Create a GUI using:

```text
Tkinter
PyQt
```

### 4. JSON Report Generation

Allow results to be exported as:

```text
results.json
```

### 5. Unit Testing

Add tests for:

```text
calculate_entropy()
has_sequence()
has_keyboard_pattern()
analyze_password()
get_rating()
check_hibp_pwned()
```

### 6. Web API

Convert the project into an API using:

```text
Flask
FastAPI
Django
```

### 7. Security Dashboard

Create a web interface showing:

```text
Password Score
Entropy
Breach Status
Detected Patterns
Security Recommendations
```

---

# 🧪 Ethical Use

This project is intended for:

* Cybersecurity education
* Personal security awareness
* Python programming practice
* Authorised security assessments
* Security-policy demonstrations

Do not use the application to collect or analyse passwords belonging to other people without proper authorisation.

---

# 📚 Learning Outcomes

By building this project, the developer demonstrates an understanding of how Python can be applied to cybersecurity.

Key concepts include:

```text
Python Programming
       ↓
File Handling
       ↓
String Processing
       ↓
Regular Security Checks
       ↓
Cryptography
       ↓
HTTP/API Communication
       ↓
Error Handling
       ↓
Security Analysis
       ↓
Automation
```

---

# 🏆 Portfolio Value

This project demonstrates the ability to take a real cybersecurity problem and develop a working Python-based solution.

It shows practical exposure to:

```text
Python
Cybersecurity
Cryptography
Networking
API Integration
Secure Coding
Security Automation
```

Rather than simply demonstrating Python syntax, the project applies programming concepts to a **real cybersecurity use case: credential security**.

---

# 👤 Author

## Adeleke Thaoban

**Cybersecurity | Python | Security Automation**

GitHub:

https://github.com/adelekethaoban17-cell

Project:

https://github.com/adelekethaoban17-cell/password-strength-checker

---

# ⭐ Project Status

```text
Project: Password Strength & Breach Analyzer
Author: Adeleke Thaoban
Language: Python
Type: Cybersecurity Tool
Status: Completed — Educational/Portfolio Project
Dependencies: Python Standard Library
```

---

## 📌 Disclaimer

This project is developed for educational, defensive-security, and authorised testing purposes.

The password-cracking-time calculation is theoretical and should not be treated as a guarantee of real-world security.

Always use unique, long, and unpredictable passwords and enable multi-factor authentication where available.

---

> **Learn → Code → Test → Analyse → Secure → Build# 🔐 Password Strength & Breach Analyzer
>
> **Author: Adeleke Thaoban**
>
> A Python-based cybersecurity tool that analyses password security using multiple security checks, including password complexity, common-password detection, predictable-pattern detection, entropy estimation, theoretical crack-time estimation, and breached-password detection.
>
> 🔗 **GitHub Repository:**
> **[**https://github.com/adelekethaoban17-cell/password-strength-checker**](https://github.com/adelekethaoban17-cell/password-strength-checker)**
>
> ---
>
> ## 📌 About the Project
>
> The **Password Strength & Breach Analyzer** is a cybersecurity-focused Python project developed to assess the security characteristics of passwords.
>
> The tool goes beyond simple password validation by analysing several factors that can contribute to password compromise.
>
> It evaluates:
>
> * Password length
> * Lowercase characters
> * Uppercase characters
> * Numbers
> * Special characters
> * Common passwords
> * Repeated characters
> * Sequential characters
> * Keyboard patterns
> * Estimated password entropy
> * Theoretical offline brute-force crack time
> * Exposure in known password breaches
>
> The application then produces a security score from **0–100**, assigns a password-strength rating, provides security recommendations, and checks whether the password appears in known breach data.
>
> ---
>
> # 🛡️ Cybersecurity Problem It Solves
>
> Passwords remain an important part of authentication systems, but weak, predictable, reused, and previously exposed passwords can increase the risk of account compromise.
>
> Attackers may use techniques such as:
>
> * Brute-force attacks
> * Dictionary attacks
> * Password spraying
> * Credential stuffing
> * Credential reuse
> * Previously leaked passwords
> * Automated password-guessing attacks
>
> For example:
>
> ```text
> 123456
> password
> qwerty
> admin
> password1
> ```
>
> are highly predictable passwords.
>
> A password can also satisfy basic complexity requirements while still being dangerous if it has already appeared in a data breach.
>
> This project addresses the problem by combining **password-strength analysis and breached-password detection** into one Python security tool.
>
> ---
>
> # 🎯 Project Objectives
>
> The main objectives are to:
>
> 1. Identify weak passwords.
> 2. Detect common passwords.
> 3. Identify predictable sequences.
> 4. Detect common keyboard patterns.
> 5. Detect excessive character repetition.
> 6. Estimate password entropy.
> 7. Estimate theoretical offline brute-force time.
> 8. Check passwords against known breached-password data.
> 9. Provide actionable security recommendations.
> 10. Demonstrate Python programming skills in a cybersecurity context.
>
> ---
>
> # ✨ Key Features
>
> ## 1. Password Strength Scoring
>
> The application generates a score between:
>
> ```text
> 0 – 100
> ```
>
> The score is converted into one of five ratings:
>
> |  Score | Rating      |
> | -----: | ----------- |
> |   0–29 | Very Weak   |
> |  30–49 | Weak        |
> |  50–69 | Fair        |
> |  70–89 | Strong      |
> | 90–100 | Very Strong |
>
> The score is based on several characteristics of the password.
>
> ---
>
> ## 2. Password Length Analysis
>
> Password length is an important factor in password security.
>
> The application rewards longer passwords and recommends using at least 12 characters.
>
> For example:
>
> ```text
> password
> ```
>
> is significantly less desirable than a sufficiently long, unpredictable password.
>
> ---
>
> ## 3. Character Complexity
>
> The tool checks whether the password contains:
>
> * Lowercase letters
> * Uppercase letters
> * Numbers
> * Special characters
>
> For example:
>
> ```text
> P@ssword2026!
> ```
>
> contains multiple character types.
>
> However, the project recognises that character complexity alone does n**
