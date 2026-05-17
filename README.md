# hbp100

Ultra-light privacy firewall for LLM prompts.

## Install

```bash
pip install hbp100
Usage
python
from hbp100 import sanitize

result = sanitize("Email john@example.com and OTP 123456")

print(result.text)       # Email [EMAIL_1] and OTP [OTP_1]
print(result.metadata)   # {'[OTP_1]': '123456', '[EMAIL_1]': 'john@example.com'}
What It Masks
Emails, phones, passwords, OTPs, credit cards, SSNs, API keys, JWTs, addresses, and 40+ other PII types. Context-aware: keeps horoscope years, masks birth years.

How It Works
text
Text → ML Detector → Reasoner → Masker → Safe Text
322 KB package

994 µs per request

1,000+ texts/second

License
MIT