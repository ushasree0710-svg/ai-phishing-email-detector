# 🎣 AI Phishing Email Detector

An explainable phishing detector. Give it an email's **subject** and **content** (and optionally the **sender**) and it returns a **0-100 risk score** with a plain-English explanation of every red flag it found.

## Features

| Indicator | What it looks for |
|---|---|
| **Urgency / threats** | "act now", "within 24 hours", "account will be suspended", "unusual activity" |
| **Credential requests** | "verify your password", card numbers, CVV, PIN, SSN/Aadhaar, OTP requests |
| **Suspicious links** | link text vs. real destination mismatch, raw IPs, URL shorteners, punycode, `@` trick, risky TLDs, HTTP, hyphen-stuffed domains |
| **Impersonation** | look-alike domains (`paypa1.com`), brand claimed in sender/subject but sent from another domain, authority claims from free webmail |
| **Lures** | prizes, gift cards, refunds, crypto / wire-transfer requests |
| **Attachments** | `.exe`, `.docm`, "enable macros", archives |
| **Tone** | generic greetings ("Dear customer"), shouting, excessive `!!!` |

Plus **combination bonuses** (e.g. credential request + suspicious link) because attackers combine tactics.

## How the score works

1. Each indicator group adds points; every group has a **cap** so one noisy signal cannot dominate  
   (credentials 25, links 30, urgency 20, impersonation 20, lures 10, attachments 10, tone 5).
2. Combination bonuses are added, and the total is capped at **100**.
3. Risk levels: `0-24 LOW` · `25-49 MEDIUM` · `50-74 HIGH` · `75-100 CRITICAL`.

Every point is traceable to evidence in the email, so the result is **fully explainable** (no black box).

## Project structure

```
ai-phishing-email-detector/
├── phishing_detector/
│   ├── __init__.py
│   ├── __main__.py       # python -m phishing_detector
│   ├── cli.py            # command-line interface
│   ├── detector.py       # scoring engine (caps, bonuses, levels, summary)
│   ├── indicators.py     # all indicator checks
│   ├── brands.py         # brand registry + typosquat / homoglyph detection
│   ├── links.py          # URL extraction + domain helpers
│   └── models.py         # Finding / Link / Report dataclasses
├── samples/              # example phishing + legitimate emails
├── tests/test_detector.py
├── app.py                # Streamlit web UI
├── requirements.txt
├── LICENSE
└── README.md
```

## Setup

Requires **Python 3.8+**. The core detector uses only the standard library.

```bash
git clone https://github.com/<your-username>/ai-phishing-email-detector.git
cd ai-phishing-email-detector
pip install -r requirements.txt      # only needed for the web UI
```

## Usage

**Command line**

```bash
python -m phishing_detector --subject "URGENT: verify account" \
  --body "Your account will be suspended. Log in at http://bit.ly/abc and enter your password"

python -m phishing_detector --file samples/phishing_paypal.txt
python -m phishing_detector --eml message.eml --json
python -m phishing_detector --demo        # score every email in samples/
```

**Web UI**

```bash
streamlit run app.py
```

**As a library**

```python
from phishing_detector import analyze_email

report = analyze_email(
    subject="Urgent: your account is suspended",
    body="Verify your password at http://paypa1-secure-login.com/verify",
    sender="PayPal <service@paypa1-secure-login.com>",   # optional
)
print(report.score, report.level)      # 57 HIGH
for f in report.findings:
    print(f.points, f.title, f.evidence)
```

## Sample output

```
 Risk score :  89/100  [#################---]  CRITICAL
 Verdict    : Phishing - high confidence
 Summary    : Risk score 89/100 (CRITICAL). Main drivers: credential requests (24), urgency/threats (20), impersonation (20).

   [+20] Urgency or threat language  <urgency>
         seen: urgent | immediately | within 24 hours | will be suspended | unusual activity
   [+24] Requests for credentials or sensitive data  <credentials>
         seen: verify your identity | confirm your password | credit card number
   [+15] Look-alike domain imitating Paypal  <impersonation>
         why : The link domain 'paypa1' is a look-alike spelling of 'paypal'.
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limitations & future work

- Rule-based: it can be evaded by novel wording, and the brand list is finite.
- Does not check SPF/DKIM/DMARC headers, domain age, or live URL reputation.
- Planned: ML text classifier (TF-IDF + Logistic Regression) blended with the rule score, SPF/DKIM header checks, VirusTotal/Google Safe Browsing lookups, Gmail/Outlook add-in, multilingual phrase lists.

## Disclaimer

This tool is for education and awareness. Treat results as decision support, not a guarantee.

## License

MIT
