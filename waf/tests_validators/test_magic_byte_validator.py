"""
Unit tests for validators.magic_byte_validator

Run with: pytest waf/tests_validators/test_magic_byte_validator.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.validators.magic_byte_validator import detect_file_type, validate_magic_bytes


def test_detects_png_signature():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    sig = detect_file_type(data)
    assert sig is not None
    assert sig.name == "PNG"


def test_detects_jpeg_signature():
    data = b"\xff\xd8\xff" + b"\x00" * 20
    sig = detect_file_type(data)
    assert sig.name == "JPEG"


def test_detects_gif87a_and_gif89a():
    assert detect_file_type(b"GIF87a" + b"\x00" * 10).name == "GIF"
    assert detect_file_type(b"GIF89a" + b"\x00" * 10).name == "GIF"


def test_detects_bmp_signature():
    data = b"BM" + b"\x00" * 20
    assert detect_file_type(data).name == "BMP"


def test_detects_webp_signature():
    data = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 10
    assert detect_file_type(data).name == "WEBP"


def test_detects_ico_signature():
    data = b"\x00\x00\x01\x00" + b"\x00" * 10
    assert detect_file_type(data).name == "ICO"


def test_detects_pdf_signature():
    data = b"%PDF-1.4\n" + b"\x00" * 10
    assert detect_file_type(data).name == "PDF"


def test_detects_zip_based_signature():
    data = b"PK\x03\x04" + b"\x00" * 20
    assert detect_file_type(data).name.startswith("ZIP-based")


def test_no_match_for_unknown_content():
    data = b"this is just plain text, not a known file type"
    assert detect_file_type(data) is None


def test_windows_pe_flagged_dangerous():
    data = b"MZ" + b"\x00" * 20
    result = validate_magic_bytes(data, expected_extension="jpg")
    assert not result.valid
    assert result.detected.dangerous
    assert "dangerous signature" in result.reason


def test_elf_executable_flagged_dangerous():
    data = b"\x7fELF" + b"\x00" * 20
    result = validate_magic_bytes(data)
    assert not result.valid
    assert result.detected.name == "ELF executable (Linux)"


def test_java_class_flagged_dangerous():
    data = b"\xca\xfe\xba\xbe" + b"\x00" * 20
    result = validate_magic_bytes(data)
    assert not result.valid
    assert result.detected.dangerous


def test_shebang_script_flagged_dangerous():
    data = b"#!/bin/sh\necho pwned\n"
    result = validate_magic_bytes(data)
    assert not result.valid
    assert result.detected.name == "Script with shebang"


def test_empty_file_is_invalid():
    result = validate_magic_bytes(b"")
    assert not result.valid
    assert "empty" in result.reason


def test_valid_when_extension_matches_content():
    data = b"\xff\xd8\xff" + b"\x00" * 20
    result = validate_magic_bytes(data, expected_extension="jpg")
    assert result.valid
    assert result.detected.name == "JPEG"


def test_invalid_when_extension_does_not_match_content():
    # PNG bytes, but claims to be a .jpg — classic renamed-file attack
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    result = validate_magic_bytes(data, expected_extension="jpg")
    assert not result.valid
    assert "mismatch" in result.reason


def test_no_extension_provided_just_reports_detection():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    result = validate_magic_bytes(data, expected_extension=None)
    assert result.valid
    assert result.detected.name == "PNG"


def test_unknown_content_with_extension_still_invalid():
    data = b"not a real file format at all"
    result = validate_magic_bytes(data, expected_extension="png")
    assert not result.valid
    assert result.detected is None