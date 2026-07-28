"""
extension_validator.py

Validates uploaded filenames by extension. This is the *weakest* line
of defense on its own (an attacker can trivially rename shell.php to
shell.jpg), which is exactly why magic_byte_validator.py and
mime_validator.py exist too -- but it's still a useful fast first
check, and it catches specific filename-based tricks that content
inspection alone wouldn't:

1. Double extensions: "shell.php.jpg" -- some misconfigured servers
   (old Apache mod_mime setups) execute the FIRST recognized
   extension, so this uploads as an image but runs as PHP.
2. Null byte injection: "shell.php\\x00.jpg" -- older PHP/C-based
   upload handlers truncated the string at the null byte, treating
   the file as "shell.php" while the extension check saw ".jpg".
3. Trailing dots/spaces: "shell.php." or "shell.php " -- Windows
   silently strips trailing dots/spaces from filenames, so a check
   that requires an exact ".php" match can be bypassed while Windows
   still saves/executes it as shell.php.
4. Case variation: "shell.PHP", "shell.PhP" -- naive checks that only
   match lowercase extensions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Sensible default allowlist for a blog's image upload feature.
# Callers should pass their own set if they accept other file types.
DEFAULT_ALLOWED_EXTENSIONS = frozenset({"jpg", "jpeg", "png", "gif", "webp", "bmp"})

# Extensions that should never be treated as "just an image" even if
# they end up as the final extension -- these can be executed by web
# servers or interpreters in common misconfigurations.
DANGEROUS_EXTENSIONS = frozenset({
    "php", "php3", "php4", "php5", "phtml", "pht",
    "asp", "aspx", "jsp", "jspx",
    "exe", "dll", "bat", "cmd", "sh", "bash",
    "cgi", "pl", "py", "rb",
    "htaccess", "config",
    "svg",  # can embed <script>, treated as dangerous unless explicitly allowed
})

_NULL_BYTE_RE = re.compile(r"\x00")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f]")


@dataclass
class ExtensionValidationResult:
    filename: str
    extension: Optional[str]   # normalized (lowercase, no leading dot), or None if undetermined
    valid: bool
    reason: str


def _strip_trailing_dots_and_spaces(filename: str) -> str:
    """Mimics Windows filesystem behavior of silently dropping
    trailing dots/spaces, so our check sees the filename the way the
    OS will actually store/serve it."""
    return filename.rstrip(" .")


def _extract_all_extensions(filename: str) -> list[str]:
    """Returns every extension-like segment, e.g. 'shell.php.jpg' ->
    ['php', 'jpg']. Used to catch double-extension tricks."""
    parts = filename.split(".")
    if len(parts) <= 1:
        return []
    return [p.lower() for p in parts[1:] if p]


def validate_extension(
    filename: str,
    allowed_extensions: Optional[frozenset[str]] = None,
) -> ExtensionValidationResult:
    """Validate a filename against an allowlist, catching common
    filename-based bypass tricks along the way.

    Args:
        filename: the raw, as-uploaded filename (not yet sanitized).
        allowed_extensions: set of allowed extensions (lowercase, no
            dot). Defaults to DEFAULT_ALLOWED_EXTENSIONS.
    """
    allowed = allowed_extensions if allowed_extensions is not None else DEFAULT_ALLOWED_EXTENSIONS

    if not filename or not filename.strip():
        return ExtensionValidationResult(filename=filename, extension=None, valid=False, reason="empty filename")

    if _NULL_BYTE_RE.search(filename):
        return ExtensionValidationResult(
            filename=filename, extension=None, valid=False,
            reason="null byte detected in filename (possible extension-truncation bypass)",
        )

    if _CONTROL_CHAR_RE.search(filename):
        return ExtensionValidationResult(
            filename=filename, extension=None, valid=False,
            reason="control character detected in filename",
        )

    normalized = _strip_trailing_dots_and_spaces(filename)
    if normalized != filename:
        # Re-run validation on the normalized form, but note it happened.
        result = validate_extension(normalized, allowed)
        if result.valid:
            return result
        return ExtensionValidationResult(
            filename=filename, extension=result.extension, valid=False,
            reason=f"{result.reason} (after stripping trailing dots/spaces)",
        )

    all_extensions = _extract_all_extensions(normalized)
    if not all_extensions:
        return ExtensionValidationResult(filename=filename, extension=None, valid=False, reason="no extension found")

    final_extension = all_extensions[-1]

    # Double-extension check: any earlier segment that's a dangerous
    # extension is a bypass attempt, regardless of what the final one is.
    earlier_extensions = all_extensions[:-1]
    dangerous_earlier = [ext for ext in earlier_extensions if ext in DANGEROUS_EXTENSIONS]
    if dangerous_earlier:
        return ExtensionValidationResult(
            filename=filename, extension=final_extension, valid=False,
            reason=f"double extension detected: dangerous extension '.{dangerous_earlier[0]}' found before final extension",
        )

    if final_extension in DANGEROUS_EXTENSIONS:
        return ExtensionValidationResult(
            filename=filename, extension=final_extension, valid=False,
            reason=f"'.{final_extension}' is a disallowed/dangerous extension",
        )

    if final_extension not in allowed:
        return ExtensionValidationResult(
            filename=filename, extension=final_extension, valid=False,
            reason=f"'.{final_extension}' is not in the allowed extension list",
        )

    return ExtensionValidationResult(filename=filename, extension=final_extension, valid=True, reason="extension allowed")
