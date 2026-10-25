# Password Analyzer — Password Strength Checker

A Python CLI tool that evaluates password strength, detects common weaknesses, and recommends secure password practices, built as part of the Pinnacle Labs Cybersecurity Internship.

## Important

- Runs entirely offline on your own machine — no password you type is ever sent anywhere or saved to a file
- Passwords are shown only as asterisks (`*`) in the output, never printed in plain text
- This is an educational strength-checking tool, not a password manager or password generator

## Requirements

No external dependencies — pure Python standard library. Any Python 3 installation works.

## Usage

```
python password_analyzer.py
```

Type a password at the prompt and press Enter to analyze it. Type `exit` to quit.

Or analyze a single password directly without the interactive prompt:

```
python password_analyzer.py "MyP@ssw0rd123"
```

## How It Works

- Estimates entropy (in bits) from the password's length and the character pool it draws from (lowercase, uppercase, digits, symbols)
- Flags specific weaknesses: short length, presence on a common-password list, missing character types, repeated characters (`aaa`, `111`), sequential patterns (`1234`, `abcd`), and keyboard-walk patterns (`qwerty`, `asdf`)
- Combines entropy and weakness count into a strength rating from Very Weak to Very Strong
- Prints general best-practice recommendations after every analysis

## Example Run

```
PS> python password_analyzer.py
Password Strength Analyzer
Type a password to analyze it (input will be visible). Type 'exit' to quit.

Enter password: 123456

==================================================
Password: ******  (length: 6)
Estimated entropy: 19.9 bits
Strength rating: Very Weak
==================================================

Detected weaknesses:
  1. Too short (minimum recommended length is 12+ characters).
  2. This is one of the most commonly used passwords in the world.
  3. Missing lowercase letters.
  4. Missing uppercase letters.
  5. Missing special characters (e.g. ! @ # $ %).
  6. Contains a sequential pattern (e.g. '1234', 'abcd').

Recommended practices:
  - Use at least 12-16 characters; longer passwords are exponentially harder to crack.
  - Mix uppercase, lowercase, digits, and special characters.
  - Avoid dictionary words, names, and common substitutions (e.g. 'P@ssw0rd').
  - Avoid sequential (1234, abcd) or repeated (aaa, 111) patterns.
  - Never reuse the same password across multiple sites.
  - Consider using a passphrase (e.g. 'Correct-Horse-Battery-Staple-42!') or a password manager.
  - Enable two-factor authentication (2FA) wherever possible.

Enter password: exit
```

## Defensive Takeaways

- Length matters more than complexity — a long passphrase beats a short, symbol-heavy password
- Common/leaked passwords are the first thing attackers try (credential-stuffing attacks)
- Pattern-based passwords (sequential digits, keyboard walks) are trivially guessed by cracking tools
- A password manager + 2FA remains the strongest practical defense for most people

## Author

Arathi Shekhar Munavalli