"""Read-only declared-origin evidence, never package fetching or execution."""

from .review import Limits, Policy, review_bytes
from .input import InputError, read_regular_file

__all__ = ["Limits", "Policy", "review_bytes", "InputError", "read_regular_file"]
