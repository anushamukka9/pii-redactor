"""PII detectors.

Each detector scans text and returns a list of :class:`Detection` spans.
Detectors are intentionally regex + heuristic (no model weights), so they run
anywhere a pipeline runs: CI, batch ETL, or a pre-training scrub step.

Overlapping spans are resolved deterministically: longer spans win, and ties
break by detector priority order
(api_key > SSN > credit card > phone > email > IPv6 > IP > MAC > DOB).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Detection:
    """A single detected PII span."""

    kind: str  # email | phone | ssn | credit_card | ip | ipv6 | mac_address
    #          | api_key | dob
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

# IPv4 (octet range validated in the detector below).
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6: full and compressed forms; validated with the ipaddress module.
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

# MAC address: six hex octets separated by : or -.
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# Date of birth, only when explicitly labeled (keeps precision high).
_DOB_RE = re.compile(
    r"(?i)\b(?:d\.?o\.?b\.?|date of birth|birth ?date|born)\s*[:\-]?\s*"
    r"(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})\b"
)

# API keys / secrets. Provider-specific patterns first, then a labeled
# generic pattern (requires a label like "api_key =" to stay precise).
_API_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("stripe", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("openai", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
]
_GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
)


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
    return group != "00"


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


def detect_ipv6(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for m in _IPV6_RE.finditer(text):
        candidate = m.group(0).strip(":")
        try:
            ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError:
            continue
        start = m.start() + (len(m.group(0)) - len(m.group(0).lstrip(":")))
        detections.append(
            Detection(
                kind="ipv6",
                start=start,
                end=start + len(candidate),
                value=candidate,
                confidence=0.7,
            )
        )
    return detections


def detect_mac_address(text: str) -> list[Detection]:
    return [
        Detection(
            kind="mac_address",
            start=m.start(),
            end=m.end(),
            value=m.group(0),
            confidence=0.8,
        )
        for m in _MAC_RE.finditer(text)
    ]


def detect_dob(text: str) -> list[Detection]:
    """Date of birth, only when an explicit label (DOB, date of birth, born) precedes it."""
    detections: list[Detection] = []
    for m in _DOB_RE.finditer(text):
        date = m.group(1)
        parts = re.split(r"[/\-.]", date)
        try:
            month, day = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            continue
        if not (1 <= month <= 12 and 1 <= day <= 31):
            continue
        detections.append(
            Detection(
                kind="dob",
                start=m.start(1),
                end=m.end(1),
                value=date,
                confidence=0.6,
                detail="labeled date of birth",
            )
        )
    return detections


def detect_api_keys(text: str) -> list[Detection]:
    """API keys and secrets: provider patterns plus labeled generic secrets."""
    detections: list[Detection] = []
    for provider, pattern in _API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            detections.append(
                Detection(
                    kind="api_key",
                    start=m.start(),
                    end=m.end(),
                    value=m.group(0),
                    confidence=0.85,
                    detail=f"provider={provider}",
                )
            )
    for m in _GENERIC_SECRET_RE.finditer(text):
        secret = m.group(2)
        # Heuristic: a real secret mixes letters and digits; plain words do not.
        has_letter = any(c.isalpha() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        if not (has_letter and has_digit):
            continue
        detections.append(
            Detection(
                kind="api_key",
                start=m.start(2),
                end=m.end(2),
                value=secret,
                confidence=0.75,
                detail="labeled generic secret",
            )
        )
    return detections


# Priority order for overlap resolution (earlier = wins ties).
_DETECTORS: list[Callable[[str], list[Detection]]] = [
    detect_api_keys,
    detect_ssn,
    detect_credit_cards,
    detect_phone,
    detect_email,
    detect_ipv6,
    detect_ip,
    detect_mac_address,
    detect_dob,
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
