"""Rule‑based masking engine that replaces sensitive values with placeholders.

Updated to support Reasoner integration for context‑aware masking decisions.
"""

from collections import defaultdict
from typing import Dict, Tuple, Optional

from .patterns import PATTERNS, ORDERED_CATEGORIES
from .reasoner import Reasoner


class Masker:
    """Applies regex patterns sequentially, replacing matches with numbered
    placeholders and collecting the original values in a metadata dictionary.
    
    When a Reasoner is provided, only entities that the Reasoner decides to
    "MASK" are replaced. Entities marked as "KEEP" remain in the text.
    
    The masking algorithm uses a two-pass approach:
    1. Collect all matches across all categories with their positions
    2. Query the Reasoner for each match (if available)
    3. Replace from end to start to maintain index validity
    
    This ensures that overlapping patterns are handled correctly and that
    the final text preserves as much original context as possible.
    
    Example:
        >>> masker = Masker()
        >>> reasoner = Reasoner()
        >>> masked, meta = masker.mask(
        ...     "Email: john@example.com, Zodiac: 1990",
        ...     reasoner=reasoner
        ... )
        >>> masked
        'Email: [EMAIL_1], Zodiac: 1990'
        >>> meta
        {'[EMAIL_1]': 'john@example.com'}
    """

    def mask(
        self, 
        text: str, 
        reasoner: Optional[Reasoner] = None
    ) -> Tuple[str, Dict[str, str]]:
        """Scan *text* for PII, replace occurrences based on Reasoner decisions.
        
        The algorithm:
        1. Iterates through categories in ORDERED_CATEGORIES order
        2. For each match, generates a sequential placeholder
        3. If a Reasoner is provided, queries it for each match
        4. Only masks entities where the Reasoner returns "MASK"
        5. For keyword patterns, preserves the prefix and masks the value
        6. For simple patterns, replaces the entire match
        7. Sorts all matches by position (descending) for safe replacement
        8. Builds the metadata dictionary

        Args:
            text: Raw text that may contain sensitive information.
            reasoner: Optional Reasoner instance for context‑aware decisions.
                If None, all detected PII is masked (backward compatible).

        Returns:
            A 2‑tuple of ``(masked_text, metadata)`` where metadata maps
            each placeholder to its original sensitive value.
        """
        # Phase 1: Collect all matches with their metadata
        matches = self._collect_matches(text, reasoner)
        
        # Phase 2: Replace from end to start (maintains indices)
        masked_text, metadata = self._apply_replacements(text, matches)
        
        return masked_text, metadata

    def _collect_matches(
        self, 
        text: str, 
        reasoner: Optional[Reasoner] = None
    ) -> list:
        """Find all PII matches, querying the Reasoner for each.
        
        Args:
            text: Raw text to scan for PII.
            reasoner: Optional Reasoner for masking decisions.
            
        Returns:
            List of tuples: (start, end, replacement, original_value)
            Only includes matches that should be masked.
        """
        matches = []
        occupied_spans = []
        counters: dict[str, int] = defaultdict(int)

        for category in ORDERED_CATEGORIES:
            pattern_info = PATTERNS[category]
            regex = pattern_info["regex"]
            has_groups = pattern_info["has_groups"]

            for match in regex.finditer(text):
                # Skip overlapping regions (higher priority patterns win)
                if self._is_overlapping(match.start(), match.end(), occupied_spans):
                    continue

                # Extract the original value
                if has_groups:
                    original = match.group(2)
                else:
                    original = match.group(0)

                # Query the Reasoner if available
                if reasoner is not None:
                    action = reasoner.decide(text, category, original)
                    if action == "KEEP":
                        occupied_spans.append((match.start(), match.end()))
                        continue
                    # If "MASK", proceed with replacement

                # Generate placeholder and record match
                counters[category] += 1
                placeholder = f"[{category}_{counters[category]}]"

                if has_groups:
                    replacement = match.group(1) + placeholder
                else:
                    replacement = placeholder

                matches.append(
                    (match.start(), match.end(), replacement, original)
                )
                occupied_spans.append((match.start(), match.end()))

        return matches

    def _is_overlapping(
        self, 
        start: int, 
        end: int, 
        existing_spans: list
    ) -> bool:
        """Check if a new match overlaps with any previously recorded match.
        
        This prevents lower-priority patterns from masking text that was
        already captured by a higher-priority pattern.
        
        Args:
            start: Start index of the new match.
            end: End index of the new match.
            existing_spans: List of already accepted or protected spans.
            
        Returns:
            True if the new match overlaps with any existing match.
        """
        for ex_start, ex_end in existing_spans:
            if start < ex_end and end > ex_start:
                return True
        return False

    def _apply_replacements(
        self, 
        text: str, 
        matches: list
    ) -> Tuple[str, Dict[str, str]]:
        """Replace matches from end to start to maintain index validity.
        
        Args:
            text: Original text
            matches: List of (start, end, replacement, original)
            
        Returns:
            Tuple of (masked_text, metadata_dict)
        """
        # Sort by start position descending – critical for safe replacement
        matches.sort(key=lambda m: m[0], reverse=True)

        masked_text = text
        metadata: dict[str, str] = {}

        for start, end, replacement, original in matches:
            # Extract placeholder name from replacement string
            ph_start = replacement.rfind("[")
            placeholder = replacement[ph_start:]
            
            metadata[placeholder] = original
            masked_text = masked_text[:start] + replacement + masked_text[end:]

        return masked_text, metadata
