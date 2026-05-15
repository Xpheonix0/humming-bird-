"""Data structures for sanitization results."""

from dataclasses import dataclass


@dataclass
class SanitizeResult:
    """Container for the outcome of the sanitization pipeline.

    Attributes:
        text: The (possibly masked) text after processing.
        metadata: A mapping from placeholder (e.g., "[EMAIL_1]") to the original
            sensitive value.
        has_pii: ``True`` if the detector flagged the original text as containing PII.
    """

    text: str
    metadata: dict[str, str]
    has_pii: bool
