# Password Security Analyzer

A Python-based educational cybersecurity tool that analyzes password characteristics, identifies selected common weaknesses, and provides actionable recommendations.

## Features

- Analyze password length and character variety
- Detect selected common passwords
- Identify several predictable sequences and repeated patterns
- Provide recommendations based on detected weaknesses
- Hide password input in compatible terminals
- Run automated tests with pytest

## How It Works

The analyzer evaluates a password locally using a set of explicit rules. It checks character types, selected common passwords, and a limited set of predictable patterns.

The program returns structured analysis results, including detected issues and recommendations.

## Requirements

- Python 3.13 or a compatible Python version
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

## Privacy and Security

- The application analyzes input locally.
- It does not intentionally store or transmit passwords.
- Use fake passwords when experimenting or demonstrating the tool.
- Password input hiding depends on terminal support.

## Limitations

This project uses simple, rule-based checks. Its pattern list is not comprehensive, and it does not verify passwords against breach databases or estimate real-world password-cracking time.

Passing the checks does not guarantee that a password is secure. Password strength also depends on factors that this educational tool does not measure.

## Testing

The test suite covers password length, character categories, selected common passwords, predictable patterns, repeated characters, empty input, invalid input, and cases where no weakness is detected by the implemented rules.

## Future Improvements

- Expand pattern detection and edge-case testing
- Improve handling of long passphrases
- Add more detailed explanations of detected weaknesses
- Improve test coverage and project documentation

## Disclaimer

This project is intended for educational purposes and is not a replacement for a dedicated password-security assessment tool.