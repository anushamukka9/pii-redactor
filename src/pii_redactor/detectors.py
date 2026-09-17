"""PII detectors.

Each detector scans text and returns a list of :class:`Detection` spans.
Detectors are intentionally regex + heuristic (no model weights), so they run
anywhere a pipeline runs — CI, batch ETL, or a pre-training scrub step.

Overlapping spans are resolved deterministically: longer spans win, and ties
break by detector priority order (SSN > credit card > phone > email > IP).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Detection:
    """A single detected PII span."""

    kind: str  # email | phone | ssn | credit_card | ip
    start: int
    end: int
    value: str
    confidence: float = 1.0
    detail: str = ""


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# US phone: optional +1, separators of space/dot/dash/parens.
_PHONE_RE = re.compile(
    r"(?:\+?1[\s.\-]?)?(?:\(?([2-9]\d{2})\)?[\s.\-]?)([2-9]\d{2})[\s.\-]?(\d{4})"
)

# SSN: 3-2-4 digits, rejecting obvious non-SSNs (000, 666, 900-999 prefixes).
_SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")

# Credit card: 13-19 digits with common separators.
_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# IPv4 (not validating octet range strictly — heuristic detector).
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def luhn_valid(number: str) -> bool:
    """Return True when the digit string passes the Luhn checksum."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_ssn(groups: tuple[str, str, str]) -> bool:
    area, group, _ = groups
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00":
        return False
    return True


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_email(text: str) -> list[Detection]:
    return [
        Detection(kind="email", start=m.start(), end=m.end(), value=m.group(0))
        for m in _EMAIL_RE.finditer(text)
    ]


def detect_phone(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for m in _PHONE_RE.finditer(text):
        # Reject matches that are really part of a longer digit run (SSN/card).
        before = text[m.start() - 1] if m.start() > 0 else ""
        after = text[m.end()] if m.end() < len(text) else ""
        if before.isdigit() or after.isdigit():
            continue
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) not in (10, 11):
            continue
        detections.append(
            Detection(kind="phone", start=m.start(), end=m.end(), value=m.group(0))
        )
    return detections


def detect_ssn(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for m in _SSN_RE.finditer(text):
        if not _valid_ssn(m.groups()):
            continue
        detections.append(
            Detection(
                kind="ssn",
                start=m.start(),
                end=m.end(),
                value=m.group(0),
                confidence=0.95,
            )
        )
    return detections


def detect_credit_cards(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for m in _CARD_RE.finditer(text):
        candidate = m.group(0).strip()
        digits = re.sub(r"\D", "", candidate)
        if not 13 <= len(digits) <= 19:
            continue
        if not luhn_valid(digits):
            continue
        detections.append(
            Detection(
                kind="credit_card",
                start=m.start(),
                end=m.end(),
                value=candidate,
                confidence=0.9,
                detail=f"luhn_ok last4={digits[-4:]}",
            )
        )
    return detections


def detect_ip(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for m in _IP_RE.finditer(text):
        octets = m.group(0).split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            detections.append(
                Detection(
                    kind="ip",
                    start=m.start(),
                    end=m.end(),
                    value=m.group(0),
                    confidence=0.7,
                )
            )
    return detections


# Priority order for overlap resolution (earlier = wins ties).
_DETECTORS: list[Callable[[str], list[Detection]]] = [
    detect_ssn,
    detect_credit_cards,
    detect_phone,
    detect_email,
    detect_ip,
]


def detect_all(text: str) -> list[Detection]:
    """Run every detector and return non-overlapping spans, sorted by offset."""
    candidates: list[Detection] = []
    for detector in _DETECTORS:
        candidates.extend(detector(text))
    # Longer spans first so they win overlaps; stable by priority order.
    candidates.sort(key=lambda d: (d.start, -(d.end - d.start)))
    accepted: list[Detection] = []
    occupied: list[tuple[int, int]] = []
    for det in candidates:
        if any(det.start < e and det.end > s for s, e in occupied):
            continue
        accepted.append(det)
        occupied.append((det.start, det.end))
    accepted.sort(key=lambda d: d.start)
    return accepted
