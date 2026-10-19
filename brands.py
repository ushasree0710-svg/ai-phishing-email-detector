"""Brand registry + look-alike (typosquatting) detection."""
from __future__ import annotations

import re
from typing import Optional, Tuple

from .links import registered_domain

# brand name -> official registered domains
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com",
                  "microsoftonline.com", "office365.com", "sharepoint.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "axis bank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
}

ALL_OFFICIAL = set().union(*BRANDS.values())

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
            "live.com", "aol.com", "proton.me", "protonmail.com", "mail.com",
            "gmx.com", "yandex.com", "rediffmail.com"}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})


def normalize_homoglyphs(text: str) -> str:
    """Undo common character swaps (paypa1 -> paypal, rnicrosoft -> microsoft)."""
    return text.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_abuse(host: str) -> Optional[Tuple[str, str]]:
    """Return (brand, reason) if `host` imitates a known brand without being official."""
    host = host.lower().strip(".")
    if not host or registered_domain(host) in ALL_OFFICIAL:
        return None
    tokens = [t for t in re.split(r"[-.]", host) if t]
    for brand in BRANDS:
        key = brand.replace(" ", "")
        for tok in tokens:
            if tok == key or (len(key) >= 5 and tok.startswith(key)) or (len(key) >= 6 and key in tok):
                return brand, f"uses the name '{brand}' but is not an official {brand} domain"
            if len(tok) >= 4 and normalize_homoglyphs(tok) == key and tok != key:
                return brand, f"'{tok}' is a look-alike spelling of '{brand}'"
            if len(key) >= 6 and len(tok) >= 5 and levenshtein(tok, key) == 1:
                return brand, f"'{tok}' is a one-character typo of '{brand}'"
    return None
