from hbp100 import sanitize, Pield, Detector, Reasoner, SanitizeResult
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_test(name, passed, details=""):
    """Print a test result with formatting."""
    status = "✓ PASS" if passed else "✗ FAIL"
    symbol = "✅" if passed else "❌"
    print(f"{symbol} {status}: {name}")
    if details and not passed:
        print(f"   Details: {details}")


# ============================================================================
# 1. Basic Functionality Tests
# ============================================================================

def test_basic_functionality():
    """Test core functionality of the sanitize function."""
    print_section("1. BASIC FUNCTIONALITY")
    
    tests_passed = 0
    total_tests = 0
    
    # Test 1: Email masking
    total_tests += 1
    result = sanitize("Contact john@example.com for help")
    passed = ("john@example.com" not in result.text and 
              "[EMAIL_1]" in result.text and
              result.metadata["[EMAIL_1]"] == "john@example.com")
    print_test("Email masking", passed)
    if passed: tests_passed += 1
    
    # Test 2: OTP masking
    total_tests += 1
    result = sanitize("Your OTP is 123456")
    passed = ("123456" not in result.text and 
              "[OTP_1]" in result.text)
    print_test("OTP masking", passed)
    if passed: tests_passed += 1
    
    # Test 3: Password masking
    total_tests += 1
    result = sanitize("My password is supersecret123")
    passed = ("supersecret123" not in result.text and 
              "[PASSWORD_1]" in result.text)
    print_test("Password masking", passed)
    if passed: tests_passed += 1
    
    # Test 4: Credit card masking
    total_tests += 1
    result = sanitize("Card: 4111-1111-1111-1111")
    passed = "4111-1111-1111-1111" not in result.text
    print_test("Credit card masking", passed)
    if passed: tests_passed += 1
    
    # Test 5: Multiple entities
    total_tests += 1
    result = sanitize("Email alice@test.com, OTP 999888, Password secret")
    masked = result.text
    passed = ("alice@test.com" not in masked and 
              "999888" not in masked and 
              "secret" not in masked)
    print_test("Multiple entity masking", passed)
    if passed: tests_passed += 1
    
    # Test 6: Metadata correctness
    total_tests += 1
    result = sanitize("API key: sk-1234abcd")
    passed = (result.metadata.get("[API_KEY_1]") == "sk-1234abcd")
    print_test("Metadata correctness", passed)
    if passed: tests_passed += 1
    
    # Test 7: has_pii flag
    total_tests += 1
    result = sanitize("john@example.com")
    passed = result.has_pii is True
    print_test("has_pii flag (True)", passed)
    if passed: tests_passed += 1
    
    # Test 8: Clean text
    total_tests += 1
    result = sanitize("Hello world, nice weather")
    passed = result.text == "Hello world, nice weather"
    print_test("Clean text preserved", passed)
    if passed: tests_passed += 1
    
    return tests_passed, total_tests


# ============================================================================
# 2. Reasoner Context-Aware Tests
# ============================================================================

def test_reasoner():
    """Test the Reasoner's context-aware decisions."""
    print_section("2. REASONER CONTEXT-AWARE TESTS")
    
    tests_passed = 0
    total_tests = 0
    reasoner = Reasoner()
    
    # Test 9: Zodiac keeps year
    total_tests += 1
    result = reasoner.decide("What's my horoscope for 1990?", "YEAR", "1990")
    passed = result == "KEEP"
    print_test("Zodiac context keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 10: Non-zodiac masks year
    total_tests += 1
    result = reasoner.decide("I was born in 1990", "YEAR", "1990")
    passed = result == "MASK"
    print_test("Non-zodiac masks year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 11: Calendar keeps year
    total_tests += 1
    result = reasoner.decide("Convert 2024 to Hijri", "YEAR", "2024")
    passed = result == "KEEP"
    print_test("Calendar context keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 12: Email always masked in zodiac context
    total_tests += 1
    result = reasoner.decide("Horoscope for john@test.com", "EMAIL", "john@test.com")
    passed = result == "MASK"
    print_test("Email masked even in zodiac context", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 13: Password always masked in calendar context
    total_tests += 1
    result = reasoner.decide("Convert calendar password: secret", "PASSWORD", "secret")
    passed = result == "MASK"
    print_test("Password masked even in calendar context", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 14: Star sign context
    total_tests += 1
    result = reasoner.decide("My star sign is Leo for 1995", "YEAR", "1995")
    passed = result == "KEEP"
    print_test("Star sign context keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 15: Astrological sign context
    total_tests += 1
    result = reasoner.decide("Astrological sign 1988", "YEAR", "1988")
    passed = result == "KEEP"
    print_test("Astrological sign context keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 16: Hebrew date conversion
    total_tests += 1
    result = reasoner.decide("Hebrew date for 2024", "YEAR", "2024")
    passed = result == "KEEP"
    print_test("Hebrew date conversion keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 17: Nepali calendar conversion
    total_tests += 1
    result = reasoner.decide("Nepali calendar 2080", "YEAR", "2080")
    passed = result == "KEEP"
    print_test("Nepali calendar keeps year", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 18: URL token always masked
    total_tests += 1
    result = reasoner.decide("api.com?token=abc123", "URL_TOKEN", "token=abc123")
    passed = result == "MASK"
    print_test("URL token always masked", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    # Test 19: Birth year in zodiac context
    total_tests += 1
    result = reasoner.decide("Zodiac birth chart 1990", "BIRTH_YEAR", "1990")
    passed = result == "KEEP"
    print_test("Birth year in zodiac context kept", passed, f"Got: {result}")
    if passed: tests_passed += 1
    
    return tests_passed, total_tests


# ============================================================================
# 3. PII Category Coverage Tests
# ============================================================================

def test_pii_categories():
    """Test masking of various PII categories."""
    print_section("3. PII CATEGORY COVERAGE")
    
    tests_passed = 0
    total_tests = 0
    
    test_cases = [
        ("IP_ADDRESS", "Server at 192.168.1.1 is down", "192.168.1.1"),
        ("PHONE", "Call 555-123-4567 for info", "555-123-4567"),
        ("SSN", "My SSN is 123-45-6789", "123-45-6789"),
        ("PAN", "PAN card: ABCDE1234F", "ABCDE1234F"),
        ("AADHAAR", "Aadhaar: 1234 5678 9012", "1234 5678 9012"),
        ("JWT", "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", 
         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
        ("BEARER_TOKEN", "Authorization: Bearer token123abc", "token123abc"),
        ("IBAN", "IBAN: GB29NWBK60161331926819", "GB29NWBK60161331926819"),
        ("CVV", "CVV: 123", "123"),
        ("PIN", "PIN: 1234", "1234"),
        ("UPI_ID", "UPI: user@bank", "user@bank"),
        ("MAC_ADDRESS", "MAC: 00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5E"),
        ("IMEI", "IMEI: 123456789012345", "123456789012345"),
        ("PATIENT_ID", "Patient ID: P-12345", "P-12345"),
        ("ACCOUNT_NUMBER", "Account: 1234567890", "1234567890"),
    ]
    
    for category, text, sensitive_value in test_cases:
        total_tests += 1
        result = sanitize(text)
        passed = sensitive_value not in result.text
        print_test(f"{category} masking", passed, 
                  f"Expected '{sensitive_value}' to be masked in: {result.text[:50]}...")
        if passed: tests_passed += 1
    
    return tests_passed, total_tests


# ============================================================================
# 4. Performance Benchmarks
# ============================================================================

def test_performance():
    """Benchmark Pield's performance."""
    print_section("4. PERFORMANCE BENCHMARKS")
    
    # Test 1: Single call latency
    text = "My email is john@example.com and OTP is 123456"
    
    # Warm up
    sanitize(text)
    
    start = time.perf_counter()
    for _ in range(100):
        sanitize(text)
    elapsed = time.perf_counter() - start
    avg_ms = (elapsed / 100) * 1000
    
    print(f"⚡ Average sanitize() latency: {avg_ms:.3f} ms ({avg_ms*1000:.1f} µs)")
    
    # Test 2: Detector only
    detector = Detector()
    detector.has_pii(text)  # Warm up
    
    start = time.perf_counter()
    for _ in range(1000):
        detector.has_pii(text)
    elapsed = time.perf_counter() - start
    avg_us = (elapsed / 1000) * 1_000_000
    
    print(f"⚡ Average detector latency: {avg_us:.1f} µs")
    
    # Test 3: Masker only (without Reasoner)
    from hbp100.pield.masker import Masker
    masker = Masker()
    
    start = time.perf_counter()
    for _ in range(1000):
        masker.mask(text)
    elapsed = time.perf_counter() - start
    avg_us = (elapsed / 1000) * 1_000_000
    
    print(f"⚡ Average masker latency: {avg_us:.1f} µs")
    
    # Test 4: Reasoner only
    reasoner = Reasoner()
    
    start = time.perf_counter()
    for _ in range(10000):
        reasoner.decide("What's my horoscope for 1990?", "YEAR", "1990")
    elapsed = time.perf_counter() - start
    avg_us = (elapsed / 10000) * 1_000_000
    
    print(f"⚡ Average reasoner latency: {avg_us:.1f} µs")
    
    # Test 5: Throughput (texts per second)
    texts = [
        "Hello world",
        "Email: test@example.com",
        "OTP: 123456",
        "Password: secret123",
        "What's my zodiac for 1990?",
        "Convert 2024 to Hijri",
        "API key: sk-1234abcd",
        "Credit card: 4111-1111-1111-1111",
    ] * 125  # 1000 texts
    
    start = time.perf_counter()
    for t in texts:
        sanitize(t)
    elapsed = time.perf_counter() - start
    
    throughput = len(texts) / elapsed
    print(f"⚡ Throughput: {throughput:.0f} texts/second")
    
    return True  # Performance tests always "pass" (informational)


# ============================================================================
# 5. Package Information
# ============================================================================

def test_package_info():
    """Display package information."""
    print_section("5. PACKAGE INFORMATION")
    
    import hbp100 as pield
    import os
    from pathlib import Path
    
    # Version
    print(f"📦 Version: {pield.__version__}")
    
    # Size
    package_path = Path(pield.__file__).parent
    total_size = sum(f.stat().st_size for f in package_path.rglob('*') if f.is_file())
    print(f"📦 Package size: {total_size / 1024:.1f} KB ({total_size} bytes)")
    
    # Model size
    model_path = package_path / "pridel.pkl"
    if model_path.exists():
        model_size = model_path.stat().st_size
        print(f"📦 Model size: {model_size / 1024:.1f} KB ({model_size} bytes)")
    
    # Exports
    print(f"📦 Exports: {pield.__all__}")
    
    # Files
    py_files = list(package_path.glob("*.py"))
    print(f"📦 Python modules: {len(py_files)}")
    for f in sorted(py_files):
        print(f"   - {f.name} ({f.stat().st_size} bytes)")
    
    return True


# ============================================================================
# 6. Integration Tests
# ============================================================================

def test_integration():
    """Test full pipeline integration with Reasoner."""
    print_section("6. INTEGRATION TESTS")
    
    tests_passed = 0
    total_tests = 0
    
    # Test 1: Full pipeline with zodiac context
    total_tests += 1
    pield = Pield(use_reasoner=True)
    result = pield.sanitize("What's my horoscope for 1990? Email: john@example.com")
    
    # Year should be kept, email should be masked
    passed = ("1990" in result.text and 
              "john@example.com" not in result.text and
              "[EMAIL_1]" in result.text)
    print_test("Zodiac: year kept, email masked", passed)
    if passed: tests_passed += 1
    
    # Test 2: Full pipeline without Reasoner
    total_tests += 1
    pield_no_reasoner = Pield(use_reasoner=False)
    result = pield_no_reasoner.sanitize("What's my horoscope for 1990?")
    
    # Year should be masked
    passed = "1990" not in result.text or "[YEAR" in result.text
    print_test("Without Reasoner: year masked", passed)
    if passed: tests_passed += 1
    
    # Test 3: SanitizeResult structure
    total_tests += 1
    result = sanitize("test@email.com")
    passed = (isinstance(result, SanitizeResult) and
              hasattr(result, 'text') and
              hasattr(result, 'metadata') and
              hasattr(result, 'has_pii') and
              isinstance(result.text, str) and
              isinstance(result.metadata, dict) and
              isinstance(result.has_pii, bool))
    print_test("SanitizeResult structure", passed)
    if passed: tests_passed += 1
    
    # Test 4: Sequential numbering
    total_tests += 1
    result = sanitize("Email1: a@test.com, Email2: b@test.com")
    passed = ("[EMAIL_1]" in result.text and 
              "[EMAIL_2]" in result.text and
              result.metadata.get("[EMAIL_1]") == "a@test.com" and
              result.metadata.get("[EMAIL_2]") == "b@test.com")
    print_test("Sequential placeholder numbering", passed)
    if passed: tests_passed += 1
    
    # Test 5: Context preservation
    total_tests += 1
    result = sanitize("Please send to john@test.com by tomorrow")
    passed = ("Please send to" in result.text and 
              "by tomorrow" in result.text and
              "john@test.com" not in result.text)
    print_test("Context preservation", passed)
    if passed: tests_passed += 1
    
    return tests_passed, total_tests


# ============================================================================
# Main Test Runner
# ============================================================================

def main():
    """Run all tests and display summary."""
    print("\n" + "🔒" * 35)
    print("  PIELD - Ultra-Light Privacy Firewall")
    print("  Complete Test Suite")
    print("🔒" * 35)
    
    all_passed = 0
    all_total = 0
    suite_errors = 0
    
    # Run test suites
    test_suites = [
        ("Basic Functionality", test_basic_functionality),
        ("Reasoner Context", test_reasoner),
        ("PII Categories", test_pii_categories),
        ("Integration", test_integration),
    ]
    
    for name, test_func in test_suites:
        try:
            passed, total = test_func()
            all_passed += passed
            all_total += total
        except Exception as e:
            suite_errors += 1
            print(f"\n❌ ERROR in {name} tests: {e}")
    
    # Performance (always runs)
    try:
        test_performance()
    except Exception as e:
        suite_errors += 1
        print(f"\n❌ ERROR in performance tests: {e}")
    
    # Package info (always runs)
    try:
        test_package_info()
    except Exception as e:
        suite_errors += 1
        print(f"\n❌ ERROR in package info: {e}")
    
    # Final summary
    print("\n" + "=" * 70)
    print(f"  TEST SUMMARY: {all_passed}/{all_total} passed", end="")
    
    if all_passed == all_total and suite_errors == 0:
        print(" 🎉 ALL TESTS PASSED!")
    else:
        print(f" ({all_total - all_passed} failed, {suite_errors} errors)")
    
    print("=" * 70)
    
    # Size efficiency rating
    import hbp100 as pield
    from pathlib import Path
    package_path = Path(pield.__file__).parent
    total_size = sum(f.stat().st_size for f in package_path.rglob('*') if f.is_file())
    
    print(f"\n📊 Efficiency Rating:")
    print(f"   Package size: {total_size / 1024:.1f} KB")
    if total_size < 50 * 1024:
        print("   Rating: ⭐⭐⭐ ULTRA-LIGHT (< 50KB)")
    elif total_size < 100 * 1024:
        print("   Rating: ⭐⭐ VERY LIGHT (< 100KB)")
    elif total_size < 200 * 1024:
        print("   Rating: ⭐ LIGHT (< 200KB)")
    else:
        print("   Rating: Moderate")
    
    return all_passed == all_total and suite_errors == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
