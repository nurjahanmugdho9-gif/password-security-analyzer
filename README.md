# Password Security Analyzer

A Python-based educational cybersecurity tool that analyzes password characteristics, identifies selected common weaknesses, and provides actionable recommendations.

## Features

- Analyze password length and character variety
- Estimate entropy and provide a strength score from 0 to 4
- Detect selected common passwords
- Identify keyboard walks, forward/reverse sequences, and repeated patterns
- Return structured findings suitable for a future API or web interface
- Generate cryptographically secure random passwords with `secrets`
- Provide recommendations based on detected weaknesses
- Hide password input in compatible terminals
- Run automated tests with pytest

## How It Works

The analyzer evaluates a password locally using explicit rules. It checks character
types, selected common passwords, keyboard patterns, sequential runs, and repeated
blocks. It also estimates entropy from the character pool and length. Entropy is an
estimate, not a measurement of the password's real-world crack resistance.

The program returns structured analysis results, including:

- `score`: strength score from 0 (very weak) to 4 (very strong)
- `rating`: human-readable score label
- `entropy_bits`: estimated entropy
- `findings`: structured issue objects with a code, severity, message, and recommendation
- `issues` and `recommendations`: simple lists kept for easy display and compatibility

## Requirements

- Python 3.12 or a compatible Python version
- pytest for running the test suite

## Getting Started

Clone the repository and navigate to the project directory.

Run the analyzer:

```bash
python src/analyzer.py
```

Run the automated tests:

```bash
python -m pytest -v
```

If multiple Python installations are present on Windows, use the Python interpreter configured for the project.

## Project Structure

```text
password-security-analyzer/
├── README.md
├── .gitignore
├── requirements.txt
├── src/
│   └── analyzer.py
└── tests/
    └── test_analyzer.py
```

## Generating Passwords

The module exposes `generate_password(length=20, ...)`, which uses Python's
cryptographic `secrets` module rather than the non-secure `random` module:

```python
from src.analyzer import generate_password

password = generate_password(24)
print(password)
```

Generated passwords must be at least 8 characters long.

## Privacy and Security

- The application analyzes input locally.
- It does not intentionally store or transmit passwords.
- The current version does not perform breach-database lookups or network requests.
- Use fake passwords when experimenting or demonstrating the tool.
- Password input hiding depends on terminal support.

## Limitations

This project uses rule-based checks. Its pattern list is not comprehensive, it does
not verify passwords against breach databases, and its entropy estimate does not
predict an exact real-world password-cracking time.

Passing the checks does not guarantee that a password is secure. Password strength also depends on factors that this educational tool does not measure.

## Testing

The test suite covers password length, character categories, selected common
passwords, predictable patterns, repeated characters, empty input, invalid input,
strength metadata, password generation, and cases where no weakness is detected by
the implemented rules.

## Future Improvements

- Add passphrase-aware word analysis
- Add optional Have I Been Pwned k-anonymity breach checking
- Add a JSON command-line mode
- Add a web interface without storing passwords

## Disclaimer

This project is intended for educational purposes and is not a replacement for a dedicated password-security assessment tool.