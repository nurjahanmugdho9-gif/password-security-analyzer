import getpass


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
}


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


def analyze_password(password):
    """Analyze basic password characteristics and common weaknesses."""

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        return {
            "length": 0,
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digit": False,
            "has_special": False,
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

    lowered = password.lower()

    common_patterns = (
        "1234",
        "abcd",
        "qwerty",
        "password",
        "1111",
        "0000",
    )

    has_common_pattern = any(pattern in lowered for pattern in common_patterns)

    has_repeated_sequence = has_repeated_block(password)

    if has_common_pattern or has_repeated_sequence:
        issues.append("Password contains a predictable pattern.")
        recommendations.append(
            "Avoid predictable sequences, repeated characters, "
            "and common words."
        )

    if len(set(password)) == 1:
        issues.append("Password repeats the same character.")
        recommendations.append("Use a more varied, less predictable passphrase.")

    if not has_lowercase:
        recommendations.append("Consider including lowercase letters.")

    if not has_uppercase:
        recommendations.append("Consider including uppercase letters.")

    if not has_digit:
        recommendations.append("Consider including numbers if appropriate.")

    if not has_special:
        recommendations.append("Consider including symbols if appropriate.")

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

    print("\nPotential issues:")
    for issue in result["issues"]:
        print("-", issue)

    print("\nRecommendations:")
    for recommendation in result["recommendations"]:
        print("-", recommendation)

    print("\nNote: This is a basic educational check, not a guarantee of security.")


if __name__ == "__main__":
    main()