"""
mime_validator.py

Cross-checks the THREE things an uploaded file tells you about
itself, which an attacker controls independently of each other:

    1. The filename extension       (client-controlled)
    2. The declared Content-Type    (client-controlled, easily spoofed)
    3. The actual file bytes        (ground truth -- what magic_byte_validator checks)

A legitimate image upload has all three agree. An attack usually has
at least one lying: e.g. Content-Type: image/jpeg + filename shell.jpg
+ content that's actually a PHP script. This module is the final
arbiter that combines extension_validator and magic_byte_validator
results and adds the Content-Type cross-check on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .extension_validator import validate_extension, DEFAULT_ALLOWED_EXTENSIONS, ExtensionValidationResult
from .magic_byte_validator import validate_magic_bytes, MagicByteValidationResult

EXTENSION_TO_ACCEPTABLE_MIME: dict[str, frozenset[str]] = {
    "jpg": frozenset({"image/jpeg", "image/jpg"}),
    "jpeg": frozenset({"image/jpeg", "image/jpg"}),
    "png": frozenset({"image/png"}),
    "gif": frozenset({"image/gif"}),
    "webp": frozenset({"image/webp"}),
    "bmp": frozenset({"image/bmp", "image/x-ms-bmp"}),
}


@dataclass
class MimeValidationResult:
    filename: str
    declared_content_type: Optional[str]
    valid: bool
    reasons: list[str] = field(default_factory=list)
    extension_result: Optional[ExtensionValidationResult] = None
    magic_byte_result: Optional[MagicByteValidationResult] = None

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "valid"


def validate_file(
    filename: str,
    data: bytes,
    declared_content_type: Optional[str] = None,
    allowed_extensions: Optional[frozenset[str]] = None,
) -> MimeValidationResult:
    reasons: list[str] = []

    ext_result = validate_extension(filename, allowed_extensions)
    if not ext_result.valid:
        reasons.append(f"extension check failed: {ext_result.reason}")

    magic_result = validate_magic_bytes(data, expected_extension=ext_result.extension)
    if not magic_result.valid:
        reasons.append(f"content check failed: {magic_result.reason}")

    if declared_content_type is not None and ext_result.extension is not None:
        acceptable = EXTENSION_TO_ACCEPTABLE_MIME.get(ext_result.extension)
        normalized_declared = declared_content_type.split(";")[0].strip().lower()
        if acceptable is not None and normalized_declared not in acceptable:
            reasons.append(
                f"declared Content-Type '{normalized_declared}' does not match "
                f"extension '.{ext_result.extension}' (expected one of {sorted(acceptable)})"
            )

    return MimeValidationResult(
        filename=filename,
        declared_content_type=declared_content_type,
        valid=len(reasons) == 0,
        reasons=reasons,
        extension_result=ext_result,
        magic_byte_result=magic_result,
    )