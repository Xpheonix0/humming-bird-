"""Core pipeline: detector → reasoner → masker.

Updated to integrate the Reasoner between detection and masking stages.
"""

from typing import Optional
from .detector import Detector
from .masker import Masker
from .reasoner import Reasoner
from .schemas import SanitizeResult


class Pield:
    """Main privacy firewall engine with configurable components.
    
    This class allows creating multiple instances with different 
    configurations, such as using different detector models, reasoner
    policies, or masking rules.
    
    The complete pipeline:
    1. **Detector (Pridel)**: ML classifier – "Does this text contain PII?"
    2. **Reasoner**: Context analyzer – "Should this specific entity be masked?"
    3. **Masker**: Rule-based engine – "Replace sensitive values with placeholders"
    
    Attributes:
        detector: The ML detector instance for PII classification.
        reasoner: The context-aware reasoning engine.
        masker: The rule-based masking engine.
        
    Example:
        >>> # Default usage with all components
        >>> pield = Pield()
        >>> result = pield.sanitize("My zodiac sign for 1990 is Leo")
        >>> print(result.text)
        'My zodiac sign for 1990 is Leo'  # YEAR kept due to zodiac context
        >>> 
        >>> # Without Reasoner (backward compatible)
        >>> pield_no_reasoner = Pield(use_reasoner=False)
        >>> result = pield_no_reasoner.sanitize("My zodiac sign for 1990 is Leo")
        >>> print(result.text)
        'My zodiac sign for [YEAR_1] is Leo'  # YEAR masked
    """
    
    def __init__(
        self, 
        detector: Optional[Detector] = None,
        use_reasoner: bool = True
    ) -> None:
        """Initialize the privacy firewall.
        
        Args:
            detector: Optional pre-configured Detector instance. If None,
                creates a default detector that loads the bundled model.
            use_reasoner: If True (default), enables context-aware reasoning.
                Set to False for backward compatibility or when you want
                to mask all PII unconditionally.
                
        Note:
            Each Pield instance creates its own Masker and Reasoner.
            For multiple instances, consider reusing detectors to avoid
            loading the model multiple times.
        """
        self.detector = detector or Detector()
        self.reasoner = Reasoner() if use_reasoner else None
        self.masker = Masker()
    
    def sanitize(self, text: str) -> SanitizeResult:
        """Run the full privacy firewall pipeline on *text*.

        Pipeline stages:
        1. **Detection**: ML model checks if text contains PII
        2. **Reasoning**: Context-aware masking decisions for each entity
        3. **Masking**: Rule-based pattern replacement for entities to mask

        If no PII is detected in stage 1, the original text is returned
        unchanged with an empty metadata dictionary. This short-circuit
        avoids the overhead of regex processing for clean text.

        Args:
            text: The raw input string (e.g., an LLM prompt). Can be
                any length – the detector and masker both handle
                variable-length inputs.

        Returns:
            A ``SanitizeResult`` containing:
            - ``text``: The (possibly) masked text
            - ``metadata``: Mapping of placeholders to original values
            - ``has_pii``: The detector's boolean classification
            
        Example:
            >>> pield = Pield()
            >>> 
            >>> # Context-aware: year kept in zodiac query
            >>> result = pield.sanitize("What's my horoscope for 1990?")
            >>> "1990" in result.text
            True
            >>> 
            >>> # Security-first: email always masked
            >>> result = pield.sanitize("Email: john@example.com, year 1990")
            >>> "john@example.com" not in result.text
            True
            >>> "1990" not in result.text
            True
        """
        # Stage 1: ML-based PII detection
        if not self.detector.has_pii(text):
            return SanitizeResult(text=text, metadata={}, has_pii=False)
        
        # Stage 2: Context-aware reasoning (if enabled)
        # The Reasoner will be queried by the Masker for each entity
        
        # Stage 3: Rule-based masking with Reasoner integration
        masked_text, metadata = self.masker.mask(
            text,
            reasoner=self.reasoner
        )
        
        return SanitizeResult(
            text=masked_text, 
            metadata=metadata, 
            has_pii=True
        )


# Module-level convenience instance for the functional API.
# Created lazily on the first sanitize() call so imports stay lightweight.
_default_pield: Optional[Pield] = None


def sanitize(text: str) -> SanitizeResult:
    """Convenience function for one-shot sanitization using the default engine.
    
    Uses a pre-configured Pield instance with Reasoner enabled for
    context-aware masking. This is the recommended way to use Pield
    for most applications.
    
    Args:
        text: The raw input string to sanitize.

    Returns:
        A ``SanitizeResult`` with the sanitized text and metadata.
        
    Example:
        >>> from hbp100 import sanitize
        >>> 
        >>> # Horoscope context preserves years
        >>> result = sanitize("What zodiac is 1990?")
        >>> print(result.text)
        'What zodiac is 1990?'
        >>> 
        >>> # Non-horoscope context masks years
        >>> result = sanitize("I was born in 1990")
        >>> print(result.text)
        'I was born in [YEAR_1]'
    """
    global _default_pield
    if _default_pield is None:
        _default_pield = Pield()
    return _default_pield.sanitize(text)
