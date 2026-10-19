"""Command-line interface.

Examples
--------
python -m phishing_detector --subject "Urgent: verify account" --body "Click http://bit.ly/x to log in"
python -m phishing_detector --file samples/phishing_paypal.txt
python -m phishing_detector --eml message.eml --json
python -m phishing_detector --demo
"""
from __future__ import annotations

import argparse
import email
import json
import re
import sys
from email import policy
from pathlib import Path
from typing import Tuple

from .detector import analyze_email
from .models import Report

COLORS = {"LOW": "\033[92m", "MEDIUM": "\033[93m", "HIGH": "\033[91m", "CRITICAL": "\033[95m"}
RESET = "\033[0m"


def parse_email_text(raw: str) -> Tuple[str, str, str]:
    """Parse text that optionally starts with 'From:' / 'Subject:' headers."""
    if re.match(r"(?im)^(subject|from):", raw):
        msg = email.message_from_string(raw, policy=policy.default)
        body = msg.get_body(preferencelist=("html", "plain"))
        content = body.get_content() if body else (msg.get_payload() if not msg.is_multipart() else "")
        return str(msg["subject"] or ""), str(content), str(msg["from"] or "")
    return "", raw, ""


def parse_eml(path: Path) -> Tuple[str, str, str]:
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    body = msg.get_body(preferencelist=("html", "plain"))
    return str(msg["subject"] or ""), (body.get_content() if body else ""), str(msg["from"] or "")


def render(report: Report, color: bool = True) -> str:
    c = COLORS[report.level] if color else ""
    r = RESET if color else ""
    filled = report.score // 5
    bar = "#" * filled + "-" * (20 - filled)
    out = ["=" * 62, " PHISHING RISK REPORT", "=" * 62,
           f" Risk score : {c}{report.score:>3}/100  [{bar}]  {report.level}{r}",
           f" Verdict    : {report.verdict}", f" Summary    : {report.summary}", "",
           " Indicators found:"]
    if not report.findings:
        out.append("   (none)")
    for f in report.findings:
        out.append(f"   [+{f.points:<2}] {f.title}  <{f.category}>")
        out.append(f"         why : {f.detail}")
        if f.evidence:
            out.append("         seen: " + " | ".join(f.evidence))
    out += ["", " Recommended actions:"] + [f"   - {r_}" for r_ in report.recommendations] + ["=" * 62]
    return "\n".join(out)


def run_demo(color: bool) -> None:
    sample_dir = Path(__file__).resolve().parent.parent / "samples"
    for p in sorted(sample_dir.glob("*.txt")):
        subject, body, sender = parse_email_text(p.read_text(encoding="utf-8"))
        rep = analyze_email(subject, body, sender)
        print(f"{p.name:<28} -> {rep.score:>3}/100  {rep.level:<8} {rep.verdict}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishing_detector", description="AI Phishing Email Detector")
    ap.add_argument("--subject", default="", help="email subject")
    ap.add_argument("--body", default="", help="email body (text or HTML)")
    ap.add_argument("--sender", default="", help='sender, e.g. "PayPal <x@mail.com>"')
    ap.add_argument("--file", help="text file (optionally with From:/Subject: headers)")
    ap.add_argument("--eml", help=".eml email file")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("--demo", action="store_true", help="score all emails in samples/")
    args = ap.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    if args.demo:
        run_demo(color)
        return 0
    subject, body, sender = args.subject, args.body, args.sender
    if args.eml:
        subject, body, sender = parse_eml(Path(args.eml))
    elif args.file:
        subject, body, sender = parse_email_text(Path(args.file).read_text(encoding="utf-8"))
    elif not (subject or body):
        ap.error("provide --subject/--body, --file, --eml or --demo")

    report = analyze_email(subject, body, sender)
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report, color))
    return 0 if report.score < 50 else 1   # non-zero exit for HIGH/CRITICAL (handy in scripts)


if __name__ == "__main__":
    sys.exit(main())
