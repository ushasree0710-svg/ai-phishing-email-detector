"""AI Phishing Email Detector - explainable, rule-based phishing risk scoring."""
from .detector import analyze_email
from .models import Finding, Link, Report

__all__ = ["analyze_email", "Finding", "Link", "Report"]
__version__ = "1.0.0"
