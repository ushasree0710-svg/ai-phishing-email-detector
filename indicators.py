"""Individual phishing indicator checks.

Each function returns a list of `Finding` objects. Scores are combined (with
per-category caps) in detector.py.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from .brands import ALL_OFFICIAL, BRANDS, FREEMAIL, brand_abuse
from .links import get_host, is_ip, looks_like_domain, registered_domain
from .models import Finding, Link


def _compile(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.I) for p in patterns]


def _hits(patterns: List[re.Pattern], text: str) -> List[str]:
    found: List[str] = []
    for p in patterns:
        m = p.search(text)
        if m:
            found.append(" ".join(m.group(0).split()).lower())
    return found


# --------------------------------------------------------------------------- #
# 1. Urgency / fear
# --------------------------------------------------------------------------- #
URGENCY = _compile([
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b", r"\bright away\b",
    r"\basap\b|\bas soon as possible\b", r"\bfinal (notice|warning|reminder)\b",
    r"\blast (chance|warning)\b", r"\b(expires?|expiring|expired)\b",
    r"\bwithin (the next )?\d+\s*(hours?|hrs?|days?|minutes?)\b",
    r"\baction required\b", r"\bimmediate action\b",
    r"\bwill be (suspended|locked|closed|terminated|deactivated|deleted|disabled)\b",
    r"\b(has|have) been (suspended|locked|compromised|limited|disabled|restricted)\b",
    r"\b(unusual|suspicious|unauthori[sz]ed) (activity|sign[- ]?in|login|access|transaction)\b",
    r"\bfailure to (comply|respond|verify|update|act)\b",
    r"\bavoid (account )?(suspension|closure|termination|penalt(y|ies))\b",
    r"\blegal action\b", r"\bdeadline\b", r"\btime[- ]sensitive\b", r"\bdon'?t (delay|ignore)\b",
])


def check_urgency(subject: str, text: str) -> List[Finding]:
    hits = _hits(URGENCY, f"{subject}\n{text}")
    if not hits:
        return []
    pts = 4 * len(hits) + (3 if _hits(URGENCY, subject) else 0)
    return [Finding("urgency", "Urgency or threat language", pts,
                    "Phishers pressure you to act before you think. Real companies rarely "
                    "threaten instant account closure.", hits)]


# --------------------------------------------------------------------------- #
# 2. Credential / sensitive-data requests
# --------------------------------------------------------------------------- #
CREDENTIALS = _compile([
    r"\bverify (your|ur) (account|identity|password|information|details|email|login|payment)\b",
    r"\bconfirm (your|ur) (password|identity|account|details|information|login|email)\b",
    r"\b(enter|provide|submit|send|reply with|share)( us)? (your|the) [^.\n]{0,25}\b"
    r"(password|passcode|pin|otp|ssn|credentials|card (number|details)|cvv|login)\b",
    r"\bupdate (your )?(payment|billing|account|password|security|login|card)( (information|details|info))?\b",
    r"\b(log|sign)[ -]?in (to|here|now|below)\b",
    r"\bclick (here|the (link|button) below) to (log|sign|verify|confirm|update|secure|restore|unlock|reactivate)\b",
    r"\b(social security|ssn|aadhaar|pan card)\b",
    r"\b(credit|debit) card (number|details|information)\b", r"\bcvv\b",
    r"\b(send|share|provide|enter|reply with)\b[^.\n]{0,20}\b(otp|one[- ]time (password|code))\b",
    r"\bbank account (number|details|information)\b",
    r"\bre-?activate your (account|access)\b",
])


def check_credentials(text: str) -> List[Finding]:
    hits = _hits(CREDENTIALS, text)
    if not hits:
        return []
    return [Finding("credentials", "Requests for credentials or sensitive data", min(8 * len(hits), 25),
                    "Legitimate organisations never ask you to confirm passwords, PINs, OTPs or "
                    "card details through an email link.", hits)]


# --------------------------------------------------------------------------- #
# 3. Lures (prizes, money, crypto)
# --------------------------------------------------------------------------- #
LURES = _compile([
    r"\byou('ve| have)? (won|been selected)\b", r"\bcongratulations\b",
    r"\bclaim your (prize|reward|refund|gift|winnings)\b", r"\blotter(y|ies)\b",
    r"\bgift cards?\b", r"\binheritance\b", r"\bunclaimed (funds|money|refund)\b",
    r"\b(bitcoin|crypto(currency)?|wire transfer|western union)\b", r"\b(tax|irs) refund\b",
    r"\bmillion (dollars|usd)\b",
])


def check_lures(text: str) -> List[Finding]:
    hits = _hits(LURES, text)
    if not hits:
        return []
    return [Finding("lure", "Too-good-to-be-true or payment lure", min(4 * len(hits), 10),
                    "Unexpected prizes, refunds, gift cards or crypto/wire requests are classic scam hooks.", hits)]


# --------------------------------------------------------------------------- #
# 4. Tone
# --------------------------------------------------------------------------- #
GENERIC_GREETING = re.compile(
    r"\bdear (customer|user|member|client|account holder|sir ?/? ?madam|valued customer|email user)\b|"
    r"\bvalued customer\b", re.I)


def check_tone(text: str) -> List[Finding]:
    ev, pts = [], 0
    m = GENERIC_GREETING.search(text)
    if m:
        ev.append(m.group(0).lower()); pts += 3
    if text.count("!") >= 3:
        ev.append(f"{text.count('!')} exclamation marks"); pts += 2
    caps = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(caps) >= 4:
        ev.append("ALL-CAPS words: " + ", ".join(sorted(set(caps))[:4])); pts += 2
    if not ev:
        return []
    return [Finding("tone", "Generic or shouting tone", min(pts, 5),
                    "Mass-mailed phishing often uses impersonal greetings and excessive emphasis.", ev)]


# --------------------------------------------------------------------------- #
# 5. Attachments
# --------------------------------------------------------------------------- #
DANGEROUS_EXT = re.compile(r"\b[\w\- ]+\.(exe|scr|js|vbs|bat|cmd|jar|iso|lnk|docm|xlsm|pptm)\b", re.I)
ARCHIVE_EXT = re.compile(r"\b[\w\- ]+\.(zip|rar|7z)\b", re.I)
MACRO_ASK = re.compile(r"\benable (macros|content|editing)\b", re.I)
OPEN_ATTACH = re.compile(r"\b(open|view|see|download) (the )?attach(ed|ment)\b", re.I)


def check_attachments(text: str) -> List[Finding]:
    ev, pts = [], 0
    for rx, p in ((DANGEROUS_EXT, 10), (MACRO_ASK, 8), (ARCHIVE_EXT, 5), (OPEN_ATTACH, 3)):
        m = rx.search(text)
        if m:
            ev.append(m.group(0).strip().lower()); pts += p
    if not ev:
        return []
    return [Finding("attachment", "Risky attachment cues", min(pts, 10),
                    "Executables, macro-enabled Office files and archives are common malware carriers.", ev)]


# --------------------------------------------------------------------------- #
# 6. Links
# --------------------------------------------------------------------------- #
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
RISKY_TLDS = {"zip", "xyz", "top", "click", "link", "tk", "ml", "ga", "cf", "gq", "work",
              "support", "rest", "country", "icu", "buzz", "cam", "monster", "cfd", "sbs"}
LOGIN_WORDS = re.compile(r"(login|log-in|signin|sign-in|verify|secure|account|update|confirm|password|wallet|billing)", re.I)

SIGNALS: Dict[str, Tuple[str, int, str]] = {
    "mismatch": ("Link text does not match its real destination", 12,
                 "The link shows one address but actually opens a different site."),
    "ip": ("Link uses a raw IP address", 10, "Legitimate services use named domains, not bare IP addresses."),
    "punycode": ("Punycode / look-alike international domain", 8,
                 "'xn--' domains can visually imitate real sites using foreign characters."),
    "userinfo": ("'@' trick inside the URL", 8,
                 "Text before '@' is ignored by browsers and used to disguise the real host."),
    "shortener": ("URL shortener hides the destination", 6, "You can't see where a shortened link really leads."),
    "tld": ("Link uses a TLD often abused for phishing", 5, "Cheap/free TLDs are heavily used for throw-away phishing sites."),
    "keywords": ("Login/verify keywords on an unofficial domain", 4,
                 "Words like 'secure', 'verify' or 'login' on an unknown domain are a common trick."),
    "subdomains": ("Excessive subdomains", 4, "Deep subdomain chains bury the real domain."),
    "http": ("Link is not encrypted (HTTP)", 3, "Sensitive sites use HTTPS; plain HTTP is a warning sign."),
    "hyphens": ("Domain stuffed with hyphens", 3, "Hyphen-heavy domains are typical of fake 'secure-login-...' sites."),
    "long": ("Unusually long URL", 2, "Very long URLs can hide the real destination."),
}


def check_links(links: List[Link]) -> Tuple[List[Finding], Dict[str, List[str]]]:
    """Return findings for link-based signals and for brand look-alike domains."""
    found: Dict[str, List[str]] = {}
    brand_hits: Dict[str, List[str]] = {}
    reasons: Dict[str, str] = {}

    for link in links[:30]:
        url = link.url
        host = get_host(url)
        if not host:
            continue
        reg = registered_domain(host)
        abuse = brand_abuse(host)
        official = reg in ALL_OFFICIAL

        def add(key: str) -> None:
            found.setdefault(key, []).append(url)

        if looks_like_domain(link.display_text):
            shown = get_host(link.display_text)
            if shown and registered_domain(shown) != reg:
                add("mismatch")
        if abuse:
            brand_hits.setdefault(abuse[0], []).append(url)
            reasons[abuse[0]] = abuse[1]
        if official:
            continue
        if is_ip(host):
            add("ip")
        if "xn--" in host:
            add("punycode")
        if "@" in urlparse(url if "://" in url else "http://" + url).netloc:
            add("userinfo")
        if reg in SHORTENERS:
            add("shortener")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            add("tld")
        if LOGIN_WORDS.search(url):
            add("keywords")
        if len(host.split(".")) > 4:
            add("subdomains")
        if url.lower().startswith("http://"):
            add("http")
        if host.count("-") >= 3:
            add("hyphens")
        if len(url) > 100:
            add("long")

    findings = [Finding("links", SIGNALS[k][0], SIGNALS[k][1], SIGNALS[k][2], sorted(set(v))[:3])
                for k, v in found.items()]
    for brand, urls in brand_hits.items():
        findings.append(Finding("impersonation", f"Look-alike domain imitating {brand.title()}", 15,
                                f"The link domain {reasons[brand]}.", sorted(set(urls))[:3]))
    return findings, brand_hits


# --------------------------------------------------------------------------- #
# 7. Impersonation (sender + content)
# --------------------------------------------------------------------------- #
AUTHORITY = re.compile(
    r"\b(it (support|department|helpdesk|help desk)|help ?desk|security (team|department|center)|"
    r"account (team|department)|customer (support|service|care)|hr department|payroll|"
    r"system administrator|chief executive|billing department|your bank)\b", re.I)
ROLE_WORDS = r"(support|security|team|account|service|billing|customer|helpdesk|notification|alert)"


def _claimed_brands(sender_name: str, subject: str, text: str) -> List[str]:
    claimed = []
    for brand in BRANDS:
        b = re.escape(brand)
        if (re.search(rf"\b{b}\b", sender_name, re.I) or re.search(rf"\b{b}\b", subject, re.I)
                or re.search(rf"\b{b}\b[\s']{{0,3}}{ROLE_WORDS}\b", text, re.I)):
            claimed.append(brand)
    return claimed


def check_impersonation(subject: str, text: str, links: List[Link], sender: str,
                        link_brand_hits: Dict[str, List[str]]) -> List[Finding]:
    from email.utils import parseaddr
    findings: List[Finding] = []
    name, addr = parseaddr(sender or "")
    sender_dom = addr.split("@")[-1].lower() if "@" in addr else ""
    sender_reg = registered_domain(sender_dom) if sender_dom else ""
    claimed = _claimed_brands(name, subject, text)

    if sender_dom:
        abuse = brand_abuse(sender_dom)
        if abuse:
            findings.append(Finding("impersonation", f"Sender domain imitates {abuse[0].title()}", 15,
                                    f"The sender domain {abuse[1]}.", [addr]))
        else:
            for brand in claimed:
                if sender_reg not in BRANDS[brand]:
                    findings.append(Finding("impersonation", f"Claims to be {brand.title()} but sender is @{sender_reg}", 15,
                                            "Display name/subject claim a brand, but the email comes from an unrelated domain.",
                                            [sender]))
                    break
        if "@" in name and name.split("@")[-1].strip().lower() != sender_dom:
            findings.append(Finding("impersonation", "Display name contains a different email address", 8,
                                    "Spoofers put a trusted address in the display name.", [sender]))
        if sender_reg in FREEMAIL and (AUTHORITY.search(text) or claimed):
            findings.append(Finding("impersonation", "Authority/brand claim from a free email provider", 8,
                                    "Banks, IT teams and brands do not write from free webmail accounts.", [sender]))
    elif links and not link_brand_hits:
        for brand in claimed:
            if not any(registered_domain(get_host(l.url)) in BRANDS[brand] for l in links):
                findings.append(Finding("impersonation", f"Mentions {brand.title()} but links go elsewhere", 8,
                                        "The email presents itself as this brand, yet no link points to its official domain.",
                                        [l.url for l in links[:2]]))
                break
    return findings
