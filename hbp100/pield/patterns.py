"""Compiled regex patterns for all supported PII categories."""

import re

# Each entry contains:
# - 'regex': compiled pattern
# - 'has_groups': bool indicating if pattern uses keyword prefix groups
#   (group(1)=prefix, group(2)=sensitive value when True)

PATTERNS = {
    "EMAIL": {
        "regex": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "has_groups": False,
    },
    "IP_ADDRESS": {
        "regex": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "has_groups": False,
    },
    "MAC_ADDRESS": {
        "regex": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        "has_groups": False,
    },
    "URL_TOKEN": {
        "regex": re.compile(
            r"([?&](?:token|access_token|auth|api_key)=)([^&\s]+)", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "JWT": {
        "regex": re.compile(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        "has_groups": False,
    },
    "BEARER_TOKEN": {
        "regex": re.compile(
            r"(bearer\s+)([a-zA-Z0-9._\-+/]+=*)", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "ACCESS_TOKEN": {
        "regex": re.compile(
            r"(access[_\s]?token\s*[:=]\s*)([a-zA-Z0-9._\-+/=]{10,})",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "SECRET_KEY": {
        "regex": re.compile(
            r"(secret[_\s]?key\s*[:=]\s*)([a-zA-Z0-9._\-+/=]{10,})",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "API_KEY": {
        "regex": re.compile(
            r"(api[_\s]?key\s*[:=]\s*)([a-zA-Z0-9._\-]{10,})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "CREDIT_CARD": {
        "regex": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "has_groups": False,
    },
    "IBAN": {
        "regex": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"),
        "has_groups": False,
    },
    "ROUTING_NUMBER": {
        "regex": re.compile(
            r"(routing\s*(?:number|no)?\s*[:=]\s*)(\d{9})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "UPI_ID": {
        "regex": re.compile(r"[\w.\-]+@[\w.\-]+"),
        "has_groups": False,
    },
    "CVV": {
        "regex": re.compile(r"(cvv\s*[:=]\s*)(\d{3,4})", re.IGNORECASE),
        "has_groups": True,
    },
    "PAN": {
        "regex": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        "has_groups": False,
    },
    "AADHAAR": {
        "regex": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        "has_groups": False,
    },
    "SSN": {
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "has_groups": False,
    },
    "PASSPORT": {
        "regex": re.compile(
            r"(passport\s*(?:no|number)?\s*[:=]\s*)([A-Z0-9]{5,20})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "DRIVER_LICENSE": {
        "regex": re.compile(
            r"(driver\'?s?\s*licen[cs]e\s*(?:no|number)?\s*[:=]\s*)([A-Z0-9]{5,20})",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "PHONE": {
        "regex": re.compile(
            r"(?<!\d)(?=(?:\D*\d){7,15}\D*(?!\d))(?:\+?\d{1,3}[-\s]?)?\(?\d{2,4}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}(?:[-\s]?\d{2,9})?(?!\d)"
        ),
        "has_groups": False,
    },
    "PASSWORD": {
        "regex": re.compile(
            r"(password(?:\s*(?:[:=]|\bis\b)\s*|\s+))(\S{4,})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "OTP": {
        "regex": re.compile(
            r"((?:otp|one\s*time\s*(?:password|code)|verification\s*code)(?:\s*(?:[:=]|\bis\b)\s*|\s+))(\d{4,6})",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "PIN": {
        "regex": re.compile(
            r"(pin\s*[:=]\s*)(\d{4,6})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "SECURITY_ANSWER": {
        "regex": re.compile(
            r"((?:security\s*answer|answer)\s*[:=]\s*)(\S{3,})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "ACCOUNT_NUMBER": {
        "regex": re.compile(
            r"(account\s*(?:number|no|#)?\s*[:=]\s*)([\d\s-]+)",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "PATIENT_ID": {
        "regex": re.compile(
            r"(patient\s*(?:id|number|no|#)?\s*[:=]\s*)([A-Z0-9-]+)",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "PRESCRIPTION_NUMBER": {
        "regex": re.compile(
            r"(prescription\s*(?:number|no|#)?\s*[:=]\s*)([A-Z0-9-]+)",
            re.IGNORECASE,
        ),
        "has_groups": True,
    },
    "CHECK_NUMBER": {
        "regex": re.compile(
            r"(check\s*(?:number|no|#)?\s*[:=]\s*)(\d+)", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "MICR": {
        "regex": re.compile(
            r"(micr\s*(?:code|number)?\s*[:=]\s*)(\d{9})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "DP_ID": {
        "regex": re.compile(
            r"(dp\s*(?:id|number|#)?\s*[:=]\s*)([A-Z0-9]+)", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "CLIENT_ID": {
        "regex": re.compile(
            r"(client\s*(?:id|number|#)?\s*[:=]\s*)([A-Z0-9-]+)", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "BIRTH_YEAR": {
        "regex": re.compile(
            r"((?:born|birth\s*year|dob)\s*[:=]\s*)(\d{4})", re.IGNORECASE
        ),
        "has_groups": True,
    },
    "YEAR_ONLY": {
        "regex": re.compile(r"\b(19|20)\d{2}\b"),
        "has_groups": False,
    },
    "IMEI": {
        "regex": re.compile(r"\b\d{15}\b"),
        "has_groups": False,
    },
    "ADDRESS": {
        "regex": re.compile(
            r"\b\d{1,5}\s+\w+(?:\s+\w+)*?\s+(?:street|st|avenue|ave|road|rd|lane|ln|drive|dr|court|ct|way|blvd|boulevard|place|pl)\b",
            re.IGNORECASE,
        ),
        "has_groups": False,
    },
}
"""Adding a new pattern:
"NEW_CATEGORY": {
    "regex": re.compile(r"your_pattern_here"),
    "has_groups": False,  # or True if keyword-based
}

Then add to ORDERED_CATEGORIES at the right position
"""

ORDERED_CATEGORIES = [
    "EMAIL",
    "IP_ADDRESS",
    "MAC_ADDRESS",
    "URL_TOKEN",
    "JWT",
    "BEARER_TOKEN",
    "ACCESS_TOKEN",
    "SECRET_KEY",
    "API_KEY",
    "CREDIT_CARD",
    "IBAN",
    "ROUTING_NUMBER",
    "UPI_ID",
    "CVV",
    "PAN",
    "AADHAAR",
    "SSN",
    "PASSPORT",
    "DRIVER_LICENSE",
    "PASSWORD",
    "OTP",
    "PIN",
    "SECURITY_ANSWER",
    "ACCOUNT_NUMBER",
    "PATIENT_ID",
    "PRESCRIPTION_NUMBER",
    "CHECK_NUMBER",
    "MICR",
    "DP_ID",
    "CLIENT_ID",
    "BIRTH_YEAR",
    "YEAR_ONLY",
    "IMEI",
    "ADDRESS",
    "PHONE",
]
