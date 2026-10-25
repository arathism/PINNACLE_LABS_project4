"""
Password Strength Analyzer
---------------------------
Evaluates password strength, detects common weaknesses, and recommends
secure password practices. Pure standard library — no dependencies.

Usage:
    python password_analyzer.py
    python password_analyzer.py "MyP@ssw0rd123"
"""

import sys
import re
import math
import string

# A small sample of extremely common passwords (checked, not exhaustive)
COMMON_PASSWORDS = {
    "123456", "123456789", "password", "qwerty", "abc123", "111111",
    "123123", "letmein", "iloveyou", "admin", "welcome", "monkey",
    "login", "password1", "qwerty123", "dragon", "princess", "sunshine",
}


def calculate_entropy(password: str) -> float:
    """Estimate entropy in bits based on character pool size and length."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^\w\s]", password):
        pool += len(string.punctuation)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def check_weaknesses(password: str) -> list:
    """Return a list of detected weaknesses/issues."""
    issues = []

    if len(password) < 8:
        issues.append("Too short (minimum recommended length is 12+ characters).")
    elif len(password) < 12:
        issues.append("Below recommended length of 12 characters.")

    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most commonly used passwords in the world.")

    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letters.")
    if not re.search(r"\d", password):
        issues.append("Missing digits.")
    if not re.search(r"[^\w\s]", password):
        issues.append("Missing special characters (e.g. ! @ # $ %).")

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated characters (e.g. 'aaa', '111').")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()):
        issues.append("Contains a sequential pattern (e.g. '1234', 'abcd').")

    if re.search(r"(qwerty|asdf|zxcv)", password.lower()):
        issues.append("Contains a keyboard-walk pattern (e.g. 'qwerty', 'asdf').")

    return issues


def strength_label(entropy: float, issue_count: int) -> str:
    if entropy < 28 or issue_count >= 4:
        return "Very Weak"
    elif entropy < 36 or issue_count >= 3:
        return "Weak"
    elif entropy < 60 or issue_count >= 2:
        return "Moderate"
    elif entropy < 80 or issue_count >= 1:
        return "Strong"
    else:
        return "Very Strong"


def recommendations(issues: list) -> list:
    """General best-practice recommendations, independent of the specific password."""
    tips = [
        "Use at least 12-16 characters; longer passwords are exponentially harder to crack.",
        "Mix uppercase, lowercase, digits, and special characters.",
        "Avoid dictionary words, names, and common substitutions (e.g. 'P@ssw0rd').",
        "Avoid sequential (1234, abcd) or repeated (aaa, 111) patterns.",
        "Never reuse the same password across multiple sites.",
        "Consider using a passphrase (e.g. 'Correct-Horse-Battery-Staple-42!') or a password manager.",
        "Enable two-factor authentication (2FA) wherever possible.",
    ]
    return tips


def analyze_password(password: str) -> None:
    entropy = calculate_entropy(password)
    issues = check_weaknesses(password)
    label = strength_label(entropy, len(issues))

    print("\n" + "=" * 50)
    print(f"Password: {'*' * len(password)}  (length: {len(password)})")
    print(f"Estimated entropy: {entropy:.1f} bits")
    print(f"Strength rating: {label}")
    print("=" * 50)

    if issues:
        print("\nDetected weaknesses:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    else:
        print("\nNo major weaknesses detected.")

    print("\nRecommended practices:")
    for tip in recommendations(issues):
        print(f"  - {tip}")
    print()


def main():
    if len(sys.argv) > 1:
        password = sys.argv[1]
        analyze_password(password)
    else:
        print("Password Strength Analyzer")
        print("Type a password to analyze it (input will be visible). Type 'exit' to quit.\n")
        while True:
            password = input("Enter password: ")
            if password.lower() == "exit":
                break
            if not password:
                continue
            analyze_password(password)


if __name__ == "__main__":
    main()