"""pield – Ultra-light privacy firewall for LLM prompts.

A lightweight package that detects and masks Personally Identifiable 
Information (PII) in text using a combination of ML classification,
context-aware reasoning, and rule-based pattern matching.

Main Components:
    - Detector: ML-based PII detection using sklearn pipeline
    - Reasoner: Context-aware masking decisions
    - Pield: Core sanitization engine with configurable pipeline
    - sanitize: Convenience function for quick one-shot sanitization

Example:
    >>> from pield import sanitize
    >>> 
    >>> # Context-aware: year kept in horoscope query
    >>> result = sanitize("What's my horoscope for 1990?")
    >>> print(result.text)
    'What's my horoscope for 1990?'
    >>> 
    >>> # Security-first: email always masked
    >>> result = sanitize("Email: john@example.com")
    >>> print(result.text)
    'Email: [EMAIL_1]'
"""

from .core import sanitize, Pield
from .detector import Detector
from .reasoner import Reasoner
from .schemas import SanitizeResult

__all__ = ["sanitize", "Pield", "Detector", "Reasoner", "SanitizeResult"]
__version__ = "0.1.5"
