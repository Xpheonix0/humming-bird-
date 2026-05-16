"""
rebuild_model.py - Reconstruct sklearn Pipeline from original model parameters.

Your original pridel.pkl contains a dictionary with:
    - vocab: TF-IDF vocabulary (2360 features)
    - coef: Logistic Regression coefficients
    - intercept: Bias term
    - ngram_range: (1, 2)

This script rebuilds a proper sklearn Pipeline that has a .predict() method,
preserving ALL the original training knowledge.
"""

import joblib
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


def rebuild_model(original_path, output_path):
    """
    Reconstruct a working sklearn Pipeline from saved model parameters.
    
    Args:
        original_path: Path to the original dict pridel.pkl
        output_path: Where to save the rebuilt Pipeline
    """
    print("=" * 60)
    print("  PIELD MODEL REBUILDER")
    print("=" * 60)
    
    # ── Load original parameters ─────────────────────────────────
    print(f"\n1. Loading original model from: {original_path}")
    original = joblib.load(original_path)
    
    if not isinstance(original, dict):
        print("   ❌ Not a dictionary - no rebuild needed!")
        return
    
    vocab = original['vocab']
    coef = original['coef']
    intercept = original['intercept']
    ngram_range = original.get('ngram_range', (1, 2))
    
    print(f"   Vocabulary size:  {len(vocab)} features")
    print(f"   Coefficients:     {coef.shape}")
    print(f"   Intercept:        {intercept}")
    print(f"   N-gram range:     {ngram_range}")
    
    # ── Build TF-IDF Vectorizer ──────────────────────────────────
    print(f"\n2. Building TF-IDF vectorizer with original vocabulary...")
    
    vectorizer = TfidfVectorizer(
        vocabulary=vocab,
        ngram_range=ngram_range
    )
    
    # Fit on TWO dummy texts (both classes) to initialize internal state
    dummy_texts = ["dummy text one", "dummy text two"]
    vectorizer.fit(dummy_texts)
    print(f"   ✅ Vectorizer ready ({len(vectorizer.vocabulary_)} features)")
    
    # ── Build Classifier with Original Weights ───────────────────
    print(f"\n3. Building classifier with original coefficients...")
    
    # Create TWO samples (one per class) for initialization
    dummy_X = vectorizer.transform(dummy_texts)
    dummy_y = [0, 1]  # Both classes represented
    
    clf = LogisticRegression()
    clf.fit(dummy_X, dummy_y)
    
    # Override with original trained weights
    clf.coef_ = coef.astype(np.float64)
    clf.intercept_ = np.array([float(intercept)], dtype=np.float64)
    clf.classes_ = np.array([0, 1])
    
    print(f"   Coef shape:  {clf.coef_.shape}")
    print(f"   Intercept:   {clf.intercept_}")
    print(f"   Classes:     {clf.classes_}")
    print(f"   ✅ Classifier ready with original weights")
    
    # ── Create Pipeline ──────────────────────────────────────────
    print(f"\n4. Creating sklearn Pipeline...")
    
    pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('clf', clf)
    ])
    
    print(f"   ✅ Pipeline created")
    
    # ── Test the Rebuilt Model ───────────────────────────────────
    print(f"\n5. Testing rebuilt model...")
    
    test_cases = [
        ("my email is john@example.com", 1, "PII email"),
        ("password: secret123", 1, "PII password"),
        ("OTP: 123456", 1, "PII OTP"),
        ("credit card 4111-1111-1111-1111", 1, "PII credit card"),
        ("hello world nice weather", 0, "Clean text"),
        ("how are you today", 0, "Clean text"),
        ("API key: sk-1234abcd", 1, "PII API key"),
        ("the weather is nice", 0, "Clean text"),
        ("what time is the meeting", 0, "Clean text"),
        ("my phone number is 555-1234", 1, "PII phone"),
    ]
    
    all_passed = True
    for text, expected, description in test_cases:
        prediction = pipeline.predict([text])[0]
        status = "✅" if prediction == expected else "❌"
        if prediction != expected:
            all_passed = False
        print(f"   {status} {description:18} → {prediction} (expected {expected})")
    
    # ── Save ─────────────────────────────────────────────────────
    print(f"\n6. Saving rebuilt model to: {output_path}")
    joblib.dump(pipeline, output_path)
    
    file_size = output_path.stat().st_size
    print(f"   ✅ Saved successfully!")
    print(f"   File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
    
    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'='*60}")
    if all_passed:
        print("  ✅ MODEL REBUILT SUCCESSFULLY!")
    else:
        print("  ⚠️  Model rebuilt but some tests failed")
    print(f"{'='*60}")
    
    return pipeline


if __name__ == "__main__":
    # Paths
    ORIGINAL = Path("pridel/model/pridel.pkl")    # Your original dict
    OUTPUT = Path("pridel/model/pridel.pkl")       # Overwrite with working model
    BACKUP = Path("pridel/model/pridel.pkl.bak")   # Backup of original
    
    # Skip if already rebuilt
    if ORIGINAL.exists():
        # Check if it's already a Pipeline
        test_load = joblib.load(ORIGINAL)
        if hasattr(test_load, 'predict') and not isinstance(test_load, dict):
            print("✅ Model is already a working Pipeline - no rebuild needed!")
            print(f"   Type: {type(test_load).__name__}")
            exit(0)
    
    # Backup original first
    if ORIGINAL.exists():
        print(f"Backing up original to: {BACKUP}")
        import shutil
        shutil.copy2(ORIGINAL, BACKUP)
    
    # Rebuild
    pipeline = rebuild_model(ORIGINAL, OUTPUT)
    
    print(f"\nNext steps:")
    print(f"  pip install -e . --force-reinstall --no-deps")
    print(f"  python -m hbp100.test.test")