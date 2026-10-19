
import pytest

from src.analyzer import analyze_password


def test_password_length():
    result = analyze_password("MapleRiver27!")
    assert result["length"] == 13


def test_character_types():
    result = analyze_password("MapleRiver27!")

    assert result["has_lowercase"] is True
    assert result["has_uppercase"] is True
    assert result["has_digit"] is True
    assert result["has_special"] is True


def test_short_password_is_flagged():
    result = analyze_password("Ab1!")

    assert any(
        "shorter than 12 characters" in issue
        for issue in result["issues"]
    )


def test_common_password_is_flagged():
    result = analyze_password("password123")

    assert any(
        "common weak password" in issue
        for issue in result["issues"]
    )


def test_predictable_sequence_is_flagged():
    result = analyze_password("Hello1234World!")

    assert any(
        "predictable pattern" in issue
        for issue in result["issues"]
    )


def test_repeated_sequence_is_flagged():
    result = analyze_password("abcabcabcabc")

    assert any(
        "predictable pattern" in issue
        for issue in result["issues"]
    )

def test_repeated_character_is_flagged():
    result = analyze_password("aaaaaaaaaaaa")

    assert any(
        "repeats the same character" in issue
        for issue in result["issues"]
    )


def test_empty_password():
    result = analyze_password("")

    assert result["length"] == 0
    assert "Password cannot be empty." in result["issues"]


def test_non_string_input_raises_error():
    with pytest.raises(TypeError):
        analyze_password(12345)


def test_no_basic_weakness_detected():
    result = analyze_password("MapleRiverCloud27!")

    assert result["issues"] == [
        "No known weakness was detected by the basic checks. "
        "This does not guarantee that the password is secure."
    ]
    assert result["recommendations"] == []