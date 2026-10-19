"""Streamlit web UI.  Run with:  streamlit run app.py"""
from pathlib import Path

import streamlit as st

from phishing_detector import analyze_email
from phishing_detector.cli import parse_email_text

st.set_page_config(page_title="AI Phishing Email Detector", page_icon="🎣", layout="centered")
st.title("🎣 AI Phishing Email Detector")
st.caption("Paste an email's subject and content to get an explainable phishing risk score.")

samples = {p.stem.replace("_", " "): p for p in sorted((Path(__file__).parent / "samples").glob("*.txt"))}
choice = st.selectbox("Load a sample (optional)", ["-- none --"] + list(samples))
sub0, body0, from0 = ("", "", "")
if choice != "-- none --":
    sub0, body0, from0 = parse_email_text(samples[choice].read_text(encoding="utf-8"))

sender = st.text_input("Sender (optional)", value=from0, placeholder='PayPal Support <help@example.com>')
subject = st.text_input("Subject", value=sub0)
body = st.text_area("Email content (plain text or HTML)", value=body0, height=220)

if st.button("Analyze", type="primary"):
    if not (subject.strip() or body.strip()):
        st.warning("Please enter a subject and/or email content.")
    else:
        r = analyze_email(subject, body, sender)
        icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}[r.level]
        st.subheader(f"{icon} {r.score}/100 - {r.level}")
        st.progress(r.score / 100)
        st.write(f"**{r.verdict}.** {r.summary}")

        st.markdown("### Why this score")
        if not r.findings:
            st.success("No phishing indicators were detected.")
        for f in r.findings:
            with st.expander(f"+{f.points}  {f.title}  ({f.category})"):
                st.write(f.detail)
                for e in f.evidence:
                    st.code(e, language=None)

        st.markdown("### What to do")
        for rec in r.recommendations:
            st.write(f"- {rec}")
