"""Academic cryptography failure-mode lessons.

The ``feltcrypto.weak`` namespace is intentionally insecure and exists only
for bundled, local demonstrations. Real applications should use
``feltcrypto.safe_api``.
"""

from importlib.metadata import PackageNotFoundError, version

from feltcrypto import foundations, safe_api
from feltcrypto.foundations import parse_bytes
from feltcrypto.models import DemoResult, Lesson, LessonSummary
from feltcrypto.registry import get_lesson, list_lessons, run_all_lessons, run_lesson
from feltcrypto.safe_api import (
    decode_package,
    decrypt,
    encode_package,
    encrypt,
    generate_key,
)

try:
    __version__ = version("feltcrypto")
except PackageNotFoundError:
    __version__ = "0.1.2"

__all__ = [
    "DemoResult",
    "Lesson",
    "LessonSummary",
    "__version__",
    "decode_package",
    "decrypt",
    "encode_package",
    "encrypt",
    "foundations",
    "generate_key",
    "get_lesson",
    "list_lessons",
    "parse_bytes",
    "run_all_lessons",
    "run_lesson",
    "safe_api",
]
