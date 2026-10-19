"""Core engine: runs all indicators and produces an explainable risk score."""
from __future__ import annotations

import html
import re
from typing import Dict, List

from .indicators import (check_attachments, check_credentials, check_impersonation,
                         check_links, check_lures, check_tone, check_urgency)
from .links import extract_links
from .models import Finding, Report

# Maximum points a single category can contribute (sum of caps = 120, final score capped at 100)
CATEGORY_CAPS: Dict[str, int] = {
    "credentials": 25, "links": 30, "urgency": 20, "impersonation": 20,
    "lure": 10, "attachment": 10, "tone": 5,
}
CATEGORY_LABELS = {
    "credentials": "credential requests", "links": "suspicious links", "urgency": "urgency/threats",
    "impersonation": "impersonation", "lure": "lures", "attachment": "risky attachments", "tone": "tone",
}

LEVELS = [  # (min score, level, verdict)
    (75, "CRITICAL", "Phishing - high confidence"),
    (50, "HIGH", "Likely phishing"),
    (25, "MEDIUM", "Suspicious - verify before acting"),
    (0, "LOW", "Likely legitimate"),
]


def visible_text(body: str) -> str:
    """Strip HTML (if any) and normalise whitespace."""
    if re.search(r"(?i)<(html|body|a\s|p>|p\s|div|br|span|table)", body):
        body = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", body)
        body = re.sub(r"(?s)<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", html.unescape(body)).strip()


def _recommendations(level: str, cats: Dict[str, int]) -> List[str]:
    recs: List[str] = []
    if level in ("CRITICAL", "HIGH"):
        recs += ["Do NOT click any links, open attachments, or reply.",
                 "Report the email to your IT/security team and delete it.",
                 "If you already entered a password, change it immediately and enable MFA."]
    elif level == "MEDIUM":
        recs += ["Verify the sender through a separate channel (phone, official website).",
                 "Do not enter credentials via links in this email."]
    else:
        recs += ["No strong phishing indicators found, but stay cautious with unexpected requests."]
    if cats.get("links"):
        recs.append("Type the organisation's official address into your browser instead of using the link.")
    if cats.get("attachment"):
        recs.append("Never enable macros or run files from unverified senders.")
    return recs


def analyze_email(subject: str, body: str, sender: str = "") -> Report:
    """Analyse an email and return a Report with a 0-100 risk score and explanations."""
    subject, body, sender = subject or "", body or "", sender or ""
    text = visible_text(body)
    links = extract_links(body)

    findings: List[Finding] = []
    findings += check_urgency(subject, text)
    findings += check_credentials(f"{subject} {text}")
    findings += check_lures(f"{subject} {text}")
    findings += check_tone(text)
    findings += check_attachments(f"{subject} {text}")
    link_findings, brand_hits = check_links(links)
    findings += link_findings
    findings += check_impersonation(subject, text, links, sender, brand_hits)

    totals: Dict[str, int] = {}
    for f in findings:
        totals[f.category] = totals.get(f.category, 0) + f.points
    # Scale findings down proportionally when a category exceeds its cap, so the points
    # shown in the report match what actually counts toward the score.
    for f in findings:
        cap, total = CATEGORY_CAPS.get(f.category, 10), totals[f.category]
        if total > cap:
            f.points = max(1, round(f.points * cap / total))
    cat_scores = {c: min(v, CATEGORY_CAPS.get(c, 10)) for c, v in totals.items()}

    bonus = 0
    if cat_scores.get("credentials") and cat_scores.get("links"):
        bonus += 10
        findings.append(Finding("combination", "Credential request + suspicious link", 10,
                                "Asking for login details AND pushing a questionable link is the signature of a phishing attack.", []))
    if cat_scores.get("urgency") and cat_scores.get("credentials"):
        bonus += 5
        findings.append(Finding("combination", "Urgency + credential request", 5,
                                "Pressure combined with a data request is a strong phishing pattern.", []))
    if bonus:
        cat_scores["combination"] = bonus

    score = min(100, sum(cat_scores.values()))
    level, verdict = next((lv, vd) for th, lv, vd in LEVELS if score >= th)
    findings.sort(key=lambda f: f.points, reverse=True)

    drivers = sorted(((c, s) for c, s in cat_scores.items() if c != "combination"), key=lambda x: -x[1])[:3]
    if drivers:
        why = ", ".join(f"{CATEGORY_LABELS[c]} ({s})" for c, s in drivers)
        summary = f"Risk score {score}/100 ({level}). Main drivers: {why}."
    else:
        summary = f"Risk score {score}/100 ({level}). No phishing indicators detected."

    return Report(score=score, level=level, verdict=verdict, summary=summary, findings=findings,
                  category_scores=cat_scores, recommendations=_recommendations(level, cat_scores))
