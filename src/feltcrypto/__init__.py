"""Academic cryptography failure-mode lessons.

The ``feltcrypto.weak`` namespace is intentionally insecure and exists only
for bundled, local demonstrations. Real applications should use
``feltcrypto.safe_api``.
"""

from feltcrypto.models import DemoResult, Lesson, LessonSummary
from feltcrypto.registry import get_lesson, list_lessons, run_all_lessons, run_lesson

__all__ = [
    "DemoResult",
    "Lesson",
    "LessonSummary",
    "__version__",
    "get_lesson",
    "list_lessons",
    "run_all_lessons",
    "run_lesson",
]

__version__ = "0.1.0"
