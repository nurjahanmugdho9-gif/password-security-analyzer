import getpass
import math
import secrets
import string


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
}

COMMON_PATTERNS = (
    "1234",
    "4321",
    "abcd",
    "dcba",
    "qwerty",
    "asdf",
    "password",
    "1111",
    "0000",
)

KEYBOARD_PATTERNS = ("qwerty", "asdfgh", "zxcvbn", "1qaz", "2wsx")


def has_repeated_block(password, min_block_size=2):
    """Return True if a short block repeats to form the whole password."""
    length = len(password)

    for block_size in range(min_block_size, length // 2 + 1):
        if length % block_size != 0:
            continue

        block = password[:block_size]

        if block * (length // block_size) == password:
            return True

    return False


def calculate_entropy(password):
    """Estimate entropy from character variety and length."""
    if not password:
        return 0.0

    alphabet_size = 0
    if any(char.islower() for char in password):
        alphabet_size += 26
    if any(char.isupper() for char in password):
        alphabet_size += 26
    if any(char.isdigit() for char in password):
        alphabet_size += 10
    if any(not char.isalnum() for char in password):
        alphabet_size += 33

    return round(len(password) * math.log2(alphabet_size), 1)


def _has_sequential_run(password, minimum=4):
    lowered = password.lower()
    for index in range(len(lowered) - minimum + 1):
        chunk = lowered[index:index + minimum]
        if len(set(chunk)) != minimum or not chunk.isalnum():
            continue

        differences = [
            ord(chunk[position + 1]) - ord(chunk[position])
            for position in range(minimum - 1)
        ]
        if all(difference == 1 for difference in differences):
            return True
        if all(difference == -1 for difference in differences):
            return True
    return False


def _contains_predictable_pattern(password):
    lowered = password.lower()
    return (
        any(pattern in lowered for pattern in COMMON_PATTERNS)
        or any(pattern in lowered for pattern in KEYBOARD_PATTERNS)
        or has_repeated_block(password)
        or _has_sequential_run(password)
    )


def _rating_for_score(score):
    return ("Very weak", "Weak", "Fair", "Good", "Very strong")[score]


def generate_password(length=20, use_uppercase=True, use_digits=True,
                      use_symbols=True):
    """Generate a cryptographically secure random password."""
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("Length must be an integer.")
    if length < 8:
        raise ValueError("Length must be at least 8 characters.")

    alphabet = string.ascii_lowercase
    if use_uppercase:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += string.punctuation

    return "".join(secrets.choice(alphabet) for _ in range(length))


def analyze_password(password):
    """Analyze password characteristics, weaknesses, and estimated strength."""

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        return {
            "length": 0,
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digit": False,
            "has_special": False,
            "entropy_bits": 0.0,
            "score": 0,
            "rating": "Very weak",
            "findings": [{
                "code": "empty",
                "severity": "critical",
                "message": "Password cannot be empty.",
                "recommendation": "Enter a password to analyze.",
            }],
            "issues": ["Password cannot be empty."],
            "recommendations": ["Enter a password to analyze."],
        }

    length = len(password)

    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(not char.isalnum() for char in password)

    issues = []
    recommendations = []

    if length < 12:
        issues.append("Password is shorter than 12 characters.")
        recommendations.append("Consider using a longer password or passphrase.")

    if password.lower() in COMMON_PASSWORDS:
        issues.append("Password matches a common weak password.")
        recommendations.append("Avoid common passwords and predictable defaults.")

    findings = []

    if _contains_predictable_pattern(password):
        issues.append("Password contains a predictable pattern.")
        recommendations.append(
            "Avoid predictable sequences, repeated characters, "
            "and common words."
        )
        findings.append({
            "code": "predictable_pattern",
            "severity": "high",
            "message": "Password contains a predictable pattern.",
            "recommendation": recommendations[-1],
        })

    if len(set(password)) == 1:
        issues.append("Password repeats the same character.")
        recommendations.append("Use a more varied, less predictable passphrase.")
        findings.append({
            "code": "repeated_character",
            "severity": "high",
            "message": "Password repeats the same character.",
            "recommendation": recommendations[-1],
        })

    if length < 12:
        findings.append({
            "code": "short_password",
            "severity": "medium",
            "message": "Password is shorter than 12 characters.",
            "recommendation": recommendations[0],
        })

    if password.lower() in COMMON_PASSWORDS:
        findings.append({
            "code": "common_password",
            "severity": "critical",
            "message": "Password matches a common weak password.",
            "recommendation": recommendations[1 if length < 12 else 0],
        })

    if not has_lowercase:
        recommendations.append("Consider including lowercase letters.")

    if not has_uppercase:
        recommendations.append("Consider including uppercase letters.")

    if not has_digit:
        recommendations.append("Consider including numbers if appropriate.")

    if not has_special:
        recommendations.append("Consider including symbols if appropriate.")

    entropy_bits = calculate_entropy(password)
    score = 0
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if entropy_bits >= 50:
        score += 1
    if entropy_bits >= 75 and not _contains_predictable_pattern(password):
        score += 1
    if password.lower() in COMMON_PASSWORDS or len(set(password)) == 1:
        score = 0
    score = max(0, min(score, 4))

    if not issues:
        issues.append(
            "No known weakness was detected by the basic checks. "
            "This does not guarantee that the password is secure."
        )

    return {
        "length": length,
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy_bits": entropy_bits,
        "score": score,
        "rating": _rating_for_score(score),
        "findings": findings,
        "issues": issues,
        "recommendations": recommendations,
    }


def main():
    password = getpass.getpass("Enter a test password (input hidden): ")
    result = analyze_password(password)

    print("\n=== Password Security Analysis ===")
    print("Length:", result["length"])
    print("Lowercase letters:", result["has_lowercase"])
    print("Uppercase letters:", result["has_uppercase"])
    print("Numbers:", result["has_digit"])
    print("Symbols:", result["has_special"])
    print("Estimated entropy:", result["entropy_bits"], "bits")
    print("Strength:", result["rating"], f"({result['score']}/4)")

    print("\nPotential issues:")
    for issue in result["issues"]:
        print("-", issue)

    print("\nRecommendations:")
    for recommendation in result["recommendations"]:
        print("-", recommendation)

    print(
        "\nNote: This is an estimate based on local checks, "
        "not a guarantee of security."
    )


if __name__ == "__main__":
    main()