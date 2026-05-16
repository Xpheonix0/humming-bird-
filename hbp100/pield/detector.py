"""Lightweight ML detector that uses a pre‑trained model (pridel).

The model is an sklearn pipeline that handles TF-IDF vectorization internally,
so raw text can be passed directly to its predict method.
"""

from importlib.resources import files


class Detector:
    """Binary classifier that decides whether a text contains any PII.

    The underlying model is an sklearn pipeline that handles TF-IDF 
    vectorization internally, meaning it expects raw strings and performs 
    feature extraction as part of the pipeline.
    
    This design keeps the interface simple while allowing the model to
    be swapped for any sklearn-compatible pipeline.
    
    Attributes:
        model: The loaded sklearn pipeline with a ``predict`` method that
            accepts a list of strings and returns an array of predictions.
            
    Example:
        >>> detector = Detector()
        >>> detector.has_pii("My email is john@example.com")
        True
        >>> detector.has_pii("Hello world")
        False
    """

    def __init__(self) -> None:
        """Load the serialized sklearn pipeline from package resources.
        
        The model is expected at ``pield/pridel.pkl`` relative to the
        package installation directory. It uses ``importlib.resources``
        to locate the file robustly, even when the package is installed
        as a zip archive or wheel.
        
        Raises:
            FileNotFoundError: If ``pridel.pkl`` is missing from the package.
            joblib.exceptions.JoblibException: If the file exists but cannot
                be deserialized (e.g., incompatible sklearn version).
        """
        import joblib

        model_path = files("hbp100") / "pridel" / "model" / "pridel.pkl"
        self.model = joblib.load(model_path)

    def has_pii(self, text: str) -> bool:
        """Return ``True`` if the text is predicted to contain PII.

        The model's pipeline handles all preprocessing (TF-IDF, feature
        selection, classification) internally. We simply pass the raw
        text as a single-element list.

        Args:
            text: Input string to classify. Can be any length since
                the TF-IDF vectorizer handles variable-length inputs.

        Returns:
            ``True`` if PII is detected, ``False`` otherwise.
            
        Performance Note:
            The first call may be slower due to sklearn's internal
            just-in-time compilation. Subsequent calls are fast
            (typically < 100µs for short texts).
        """
        # sklearn predict expects a list/array of samples
        prediction = self.model.predict([text])[0]
        return bool(prediction)
