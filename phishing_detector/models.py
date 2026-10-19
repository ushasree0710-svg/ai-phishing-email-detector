"""Data structures shared across the detector."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List


@dataclass
class Link:
    """A URL found in the email, with the visible text shown to the reader (if any)."""
    url: str
    display_text: str = ""


@dataclass
class Finding:
    """One phishing indicator that fired."""
    category: str          # urgency | credentials | links | impersonation | lure | attachment | tone
    title: str
    points: int
    detail: str            # why this matters (the explanation shown to the user)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Report:
    """Final result returned to the caller."""
    score: int
    level: str
    verdict: str
    summary: str
    findings: List[Finding]
    category_scores: Dict[str, int]
    recommendations: List[str]

    def to_dict(self) -> dict:
        return asdict(self)
