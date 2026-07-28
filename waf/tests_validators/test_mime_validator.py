"""
Unit tests for validators.mime_validator

Run with: pytest waf/tests_validators/test_mime_validator.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from waf.validators.mime_validator import validate_file


PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
JPEG_BYTES = b"\xff\xd8\xff" + b"\x00" * 20


def test_fully_valid_upload_passes():
    result = validate_file(
        filename="photo.png",
        data=PNG_BYTES,
        declared_content_type="image/png",
    )
    assert result.valid
    assert result.reason == "valid"


def test_invalid_extension_fails():
    result = validate_file(
        filename="shell.php",
        data=PNG_BYTES,
        declared_content_type="image/png",
    )
    assert not result.valid
    assert "extension check failed" in result.reason


def test_content_mismatch_fails():
    # claims .png, but bytes are actually JPEG
    result = validate_file(
        filename="photo.png",
        data=JPEG_BYTES,
        declared_content_type="image/png",
    )
    assert not result.valid
    assert "content check failed" in result.reason


def test_spoofed_content_type_fails():
    # real PNG file/bytes, but Content-Type header lies
    result = validate_file(
        filename="photo.png",
        data=PNG_BYTES,
        declared_content_type="text/html",
    )
    assert not result.valid
    assert "Content-Type" in result.reason


def test_content_type_with_charset_param_is_normalized():
    result = validate_file(
        filename="photo.jpg",
        data=JPEG_BYTES,
        declared_content_type="image/jpeg; charset=binary",
    )
    assert result.valid


def test_jpg_and_jpeg_extension_both_accept_image_jpeg():
    result_jpg = validate_file("photo.jpg", JPEG_BYTES, "image/jpeg")
    result_jpeg = validate_file("photo.jpeg", JPEG_BYTES, "image/jpeg")
    assert result_jpg.valid
    assert result_jpeg.valid


def test_no_declared_content_type_skips_that_check():
    result = validate_file(
        filename="photo.png",
        data=PNG_BYTES,
        declared_content_type=None,
    )
    assert result.valid


def test_multiple_failures_all_reported():
    # bad extension AND bytes that don't match anything known
    result = validate_file(
        filename="shell.exe",
        data=b"MZ" + b"\x00" * 20,
        declared_content_type="image/png",
    )
    assert not result.valid
    assert "extension check failed" in result.reason
    assert "content check failed" in result.reason


def test_result_carries_sub_results():
    result = validate_file("photo.png", PNG_BYTES, "image/png")
    assert result.extension_result is not None
    assert result.magic_byte_result is not None
    assert result.extension_result.valid
    assert result.magic_byte_result.valid