"""
Unit tests for validators.extension_validator

Run with: pytest waf/tests_validators/test_extension_validator.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.validators.extension_validator import validate_extension, DEFAULT_ALLOWED_EXTENSIONS


def test_allows_standard_image_extensions():
    for ext in ["jpg", "jpeg", "png", "gif", "webp", "bmp"]:
        result = validate_extension(f"photo.{ext}")
        assert result.valid, f".{ext} should be allowed"


def test_rejects_php_extension():
    result = validate_extension("shell.php")
    assert not result.valid


def test_rejects_double_extension_bypass():
    result = validate_extension("shell.php.jpg")
    assert not result.valid
    assert "double extension" in result.reason


def test_rejects_double_extension_various_dangerous_types():
    for dangerous in ["asp", "jsp", "exe", "sh"]:
        result = validate_extension(f"malware.{dangerous}.png")
        assert not result.valid, f".{dangerous}.png should be rejected"


def test_rejects_null_byte_filename():
    result = validate_extension("shell.php\x00.jpg")
    assert not result.valid
    assert "null byte" in result.reason


def test_rejects_control_characters():
    result = validate_extension("shell.php\x01.jpg")
    assert not result.valid


def test_strips_trailing_dots_windows_bypass():
    # "shell.php." would be saved by Windows as "shell.php"
    result = validate_extension("shell.php.")
    assert not result.valid


def test_strips_trailing_spaces_windows_bypass():
    result = validate_extension("shell.php ")
    assert not result.valid


def test_case_insensitive_dangerous_extension():
    result = validate_extension("shell.PHP")
    assert not result.valid


def test_case_insensitive_allowed_extension():
    result = validate_extension("photo.PNG")
    assert result.valid


def test_rejects_empty_filename():
    result = validate_extension("")
    assert not result.valid


def test_rejects_no_extension():
    result = validate_extension("noextension")
    assert not result.valid


def test_svg_rejected_by_default():
    # SVG can embed <script> tags -- excluded from default allowlist
    result = validate_extension("image.svg")
    assert not result.valid


def test_custom_allowed_extensions():
    result = validate_extension("doc.pdf", allowed_extensions=frozenset({"pdf"}))
    assert result.valid


def test_custom_allowlist_still_blocks_dangerous():
    # even if caller explicitly allowlists something dangerous-adjacent,
    # double-extension trick should still be caught
    result = validate_extension("shell.php.pdf", allowed_extensions=frozenset({"pdf"}))
    assert not result.valid
