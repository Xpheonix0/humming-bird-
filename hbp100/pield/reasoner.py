"""Context‑aware reasoning engine for PII masking decisions.

The Reasoner sits between the Detector and Masker in the privacy firewall
pipeline. While the Detector answers "is there PII?", the Reasoner answers
"should this specific PII be masked?" based on context, content, and policy.

This enables intelligent decisions like keeping years in horoscope queries
while masking them in identity contexts, or preserving dates in calendar
conversion requests while masking birth years.
"""

from typing import FrozenSet


class Reasoner:
    """Decides whether each detected PII entity should be masked or preserved.
    
    The Reasoner implements a default‑deny policy: all PII is masked unless
    specific context rules indicate it should be kept. This is the safest
    approach for a privacy firewall.
    
    Design Philosophy:
        - Default: MASK everything (security first)
        - Context exceptions: KEEP when domain context clearly indicates
          the data is not personal (e.g., calendar years, zodiac signs)
        - Token exceptions: MASK even in URLs (tokens are always sensitive)
    
    Attributes:
        always_mask_categories: Frozenset of categories that are always masked
            regardless of context. These are inherently sensitive.
        zodiac_keywords: Keywords indicating astrological context where
            years may be safely shared.
        calendar_keywords: Keywords indicating calendar conversion context
            where dates may be safely shared.
    
    Example:
        >>> reasoner = Reasoner()
        >>> reasoner.decide("What's my horoscope for 1990?", "YEAR", "1990")
        'KEEP'
        >>> reasoner.decide("My birth year is 1990", "YEAR", "1990")
        'MASK'
        >>> reasoner.decide("Email me at john@example.com", "EMAIL", "john@example.com")
        'MASK'
    """

    # Categories that are ALWAYS masked – no context can override this.
    # These contain inherently sensitive personal/authentication data.
    ALWAYS_MASK: FrozenSet[str] = frozenset({
        # Identity & Contact
        "EMAIL",
        "PHONE",
        
        # Authentication (credentials are ALWAYS sensitive)
        "OTP",
        "PASSWORD",
        "PIN",
        "SECURITY_ANSWER",
        
        # Financial (always sensitive, no contextual exceptions)
        "CREDIT_CARD",
        "ACCOUNT_NUMBER",
        "IBAN",
        "ROUTING_NUMBER",
        "UPI_ID",
        "CVV",
        
        # Authentication Tokens
        "API_KEY",
        "SECRET_KEY",
        "ACCESS_TOKEN",
        "JWT",
        "BEARER_TOKEN",
        
        # Government IDs (always personal)
        "PAN",
        "AADHAAR",
        "SSN",
        "PASSPORT",
        "DRIVER_LICENSE",
    })

    # Keywords that indicate ASTROLOGICAL context where years are impersonal
    ZODIAC_KEYWORDS: FrozenSet[str] = frozenset({
        "zodiac",
        "horoscope",
        "star sign",
        "astrological sign",
        "astrology",
        "birth chart",
        "sun sign",
        "moon sign",
        "rising sign",
    })

    # Keywords that indicate CALENDAR CONVERSION context
    CALENDAR_KEYWORDS: FrozenSet[str] = frozenset({
        "convert",
        "calendar",
        "hijri",
        "bengali calendar",
        "hebrew date",
        "nepali calendar",
        "julian day",
        "shaka calendar",
        "gregorian",
        "islamic calendar",
        "chinese calendar",
        "ethiopian calendar",
        "coptic calendar",
    })

    def __init__(self) -> None:
        """Initialize the Reasoner with default masking policies.
        
        The Reasoner is stateless – all decision logic is based on
        the input parameters and class constants. This makes it
        thread‑safe and suitable for singleton use.
        """
        # No instance state needed – all policies are class constants
        pass

    def decide(self, text: str, pii_type: str, value: str) -> str:
        """Determine whether a specific PII entity should be masked or kept.
        
        Decision hierarchy:
        1. If category is in ALWAYS_MASK → MASK (no exceptions)
        2. If URL context with token parameters → MASK
        3. If astrological context and YEAR → KEEP
        4. If calendar conversion context and DATE types → KEEP
        5. Default → MASK (safe default)
        
        Args:
            text: The full original text containing the PII. Used for
                context analysis (keyword matching).
            pii_type: The category of PII (e.g., "EMAIL", "YEAR", "PHONE").
                Must match keys in patterns.py PATTERNS dict.
            value: The actual detected sensitive value. Used for URL
                analysis to check for token parameters.
        
        Returns:
            "MASK" if the entity should be replaced with a placeholder.
            "KEEP" if the entity should remain in the original text.
            
        Note:
            The return type is str not bool for future extensibility.
            A future version might return "PARTIAL_MASK" or "REDACT".
        
        Example:
            >>> r = Reasoner()
            
            # Always masked categories
            >>> r.decide("My email is john@example.com", "EMAIL", "john@example.com")
            'MASK'
            
            # Zodiac context keeps years
            >>> r.decide("What zodiac is 1990?", "YEAR", "1990")
            'KEEP'
            
            # Non-zodiac context masks years
            >>> r.decide("I was born in 1990", "YEAR", "1990")
            'MASK'
            
            # Calendar conversion keeps dates
            >>> r.decide("Convert 2024-01-15 to Hijri", "FULL_DATE", "2024-01-15")
            'KEEP'
            
            # URL tokens always masked
            >>> r.decide("GET /api?token=abc123", "URL_TOKEN", "token=abc123")
            'MASK'
        """
        # Rule 1: Always‑mask categories
        if pii_type in self.ALWAYS_MASK:
            return "MASK"

        # Rule 2: URL query parameters containing tokens
        if self._is_url_token(value):
            return "MASK"

        # Lowercase text once for all keyword checks
        text_lower = text.lower()

        # Rule 3: Astrological context – keep years
        if self._is_zodiac_context(text_lower) and pii_type in {
            "YEAR",
            "YEAR_ONLY",
            "BIRTH_YEAR",
        }:
            return "KEEP"

        # Rule 4: Calendar conversion context – keep dates
        if self._is_calendar_context(text_lower):
            if pii_type in {
                "YEAR",
                "YEAR_ONLY",
                "DATE",
                "FULL_DATE",
                "BIRTH_YEAR",  # Could be historical date, not personal
            }:
                return "KEEP"

        # Rule 5: Default – mask everything else
        return "MASK"

    def _is_zodiac_context(self, text_lower: str) -> bool:
        """Check if the text contains zodiac/horoscope keywords.
        
        Args:
            text_lower: Lowercased input text.
            
        Returns:
            True if any zodiac keyword is found in the text.
        """
        return any(keyword in text_lower for keyword in self.ZODIAC_KEYWORDS)

    def _is_calendar_context(self, text_lower: str) -> bool:
        """Check if the text contains calendar conversion keywords.
        
        Args:
            text_lower: Lowercased input text.
            
        Returns:
            True if any calendar keyword is found in the text.
        """
        return any(keyword in text_lower for keyword in self.CALENDAR_KEYWORDS)

    def _is_url_token(self, value: str) -> bool:
        """Check if a value appears to be a URL query parameter containing a token.
        
        Detects patterns like:
            - token=abc123
            - auth=xyz789
            - api_key=sk-1234
            - access_token=eyJ...
        
        Args:
            value: The detected sensitive value string.
            
        Returns:
            True if the value matches URL token parameter patterns.
        """
        value_lower = value.lower()
        
        # Check for token-related query parameters
        token_indicators = [
            "token=",
            "auth=",
            "api_key=",
            "apikey=",
            "access_token=",
            "secret=",
            "bearer=",
        ]
        
        return any(indicator in value_lower for indicator in token_indicators)
