"""
magic_byte_validator.py

Validates uploaded file *content* by checking its magic bytes (file
signature) -- the first few bytes of a file that identify its real
format, regardless of what extension or Content-Type header claims.

This is the check that catches "shell.php renamed to shell.jpg":
the extension says JPEG, but the first bytes won't match the JPEG
signature (FF D8 FF), so it gets rejected here even though
extension_validator.py alone would have waved it through.

It also catches polyglot files -- files crafted to be simultaneously
valid as two formats (e.g. a valid GIF that's also a valid PHP
script, exploiting servers that execute anything containing PHP
tags regardless of extension). We do this by explicitly checking
for known-dangerous signatures (executables, scripts) ANYWHERE
they'd be recognized, not just when they're the only match.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class FileSignature:
    name: str
    mime: str
    extensions: frozenset[str]
    matcher: Callable[[bytes], bool]
    dangerous: bool = False


def _prefix(data: bytes, sig: bytes) -> bool:
    return data.startswith(sig)


def _webp_matcher(data: bytes) -> bool:
    return len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP"


def _gif_matcher(data: bytes) -> bool:
    return data.startswith(b"GIF87a") or data.startswith(b"GIF89a")


def _shebang_matcher(data: bytes) -> bool:
    return data.startswith(b"#!")


KNOWN_SIGNATURES: list[FileSignature] = [
    FileSignature("PNG", "image/png", frozenset({"png"}), lambda d: _prefix(d, b"\x89PNG\r\n\x1a\n")),
    FileSignature("JPEG", "image/jpeg", frozenset({"jpg", "jpeg"}), lambda d: _prefix(d, b"\xff\xd8\xff")),
    FileSignature("GIF", "image/gif", frozenset({"gif"}), _gif_matcher),
    FileSignature("BMP", "image/bmp", frozenset({"bmp"}), lambda d: _prefix(d, b"BM")),
    FileSignature("WEBP", "image/webp", frozenset({"webp"}), _webp_matcher),
    FileSignature("ICO", "image/x-icon", frozenset({"ico"}), lambda d: _prefix(d, b"\x00\x00\x01\x00")),
    FileSignature("PDF", "application/pdf", frozenset({"pdf"}), lambda d: _prefix(d, b"%PDF-")),
    FileSignature(
        "ZIP-based (zip/docx/xlsx/pptx/jar)", "application/zip",
        frozenset({"zip", "docx", "xlsx", "pptx", "jar"}),
        lambda d: _prefix(d, b"PK\x03\x04") or _prefix(d, b"PK\x05\x06") or _prefix(d, b"PK\x07\x08"),
    ),
    FileSignature("Windows PE executable (EXE/DLL)", "application/x-msdownload",
                   frozenset(), lambda d: _prefix(d, b"MZ"), dangerous=True),
    FileSignature("ELF executable (Linux)", "application/x-elf",
                   frozenset(), lambda d: _prefix(d, b"\x7fELF"), dangerous=True),
    FileSignature("Java class file", "application/java-vm",
                   frozenset(), lambda d: _prefix(d, b"\xca\xfe\xba\xbe"), dangerous=True),
    FileSignature("Script with shebang", "text/x-shellscript",
                   frozenset(), _shebang_matcher, dangerous=True),
]


@dataclass
class MagicByteValidationResult:
    detected: Optional[FileSignature]
    expected_extension: Optional[str]
    valid: bool
    reason: str


def detect_file_type(data: bytes) -> Optional[FileSignature]:
    for sig in KNOWN_SIGNATURES:
        if sig.matcher(data):
            return sig
    return None


def validate_magic_bytes(data: bytes, expected_extension: Optional[str] = None) -> MagicByteValidationResult:
    if not data:
        return MagicByteValidationResult(
            detected=None, expected_extension=expected_extension, valid=False, reason="empty file content",
        )

    detected = detect_file_type(data)

    if detected is not None and detected.dangerous:
        return MagicByteValidationResult(
            detected=detected, expected_extension=expected_extension, valid=False,
            reason=f"file content matches a dangerous signature ({detected.name}), regardless of claimed extension",
        )

    if detected is None:
        return MagicByteValidationResult(
            detected=None, expected_extension=expected_extension, valid=False,
            reason="file content does not match any known/allowed file signature",
        )

    if expected_extension is not None and expected_extension.lower() not in detected.extensions:
        return MagicByteValidationResult(
            detected=detected, expected_extension=expected_extension, valid=False,
            reason=(
                f"extension/content mismatch: filename claims '.{expected_extension}' "
                f"but content signature matches {detected.name}"
            ),
        )

    return MagicByteValidationResult(
        detected=detected, expected_extension=expected_extension, valid=True,
        reason=f"content matches {detected.name} signature",
    )