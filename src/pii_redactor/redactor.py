"""Redaction with a span-level audit trail.

The :class:`Redactor` replaces detected spans with placeholders such as
``[EMAIL]`` or ``[SSN]`` and records every replacement in a
:class:`RedactionLog` — which original value (hashed, never stored raw),
where it was, and what replaced it. The audit log is what makes this
pipeline-grade: you can prove what was scrubbed, without keeping the PII.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .detectors import Detection, detect_all


PLACEHOLDERS: dict[str, str] = {
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "ssn": "[SSN]",
    "credit_card": "[CREDIT_CARD]",
    "ip": "[IP]",
}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass
class RedactionEntry:
    kind: str
    start: int
    end: int
    value_hash: str
    placeholder: str
    confidence: float


@dataclass
class RedactionLog:
    entries: list[RedactionEntry] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for e in self.entries:
            totals[e.kind] = totals.get(e.kind, 0) + 1
        return totals

    def to_dict(self) -> dict:
        return {
            "redactions": [
                {
                    "kind": e.kind,
                    "span": [e.start, e.end],
                    "value_sha256_16": e.value_hash,
                    "placeholder": e.placeholder,
                    "confidence": e.confidence,
                }
                for e in self.entries
            ],
            "counts": self.counts(),
        }


class Redactor:
    """Redact PII spans, keeping an audit log."""

    def __init__(self, placeholders: dict[str, str] | None = None):
        self.placeholders = {**PLACEHOLDERS, **(placeholders or {})}

    def redact(self, text: str) -> tuple[str, RedactionLog]:
        detections = detect_all(text)
        log = RedactionLog()
        if not detections:
            return text, log
        parts: list[str] = []
        cursor = 0
        for det in detections:
            parts.append(text[cursor:det.start])
            placeholder = self.placeholders.get(det.kind, "[REDACTED]")
            parts.append(placeholder)
            log.entries.append(
                RedactionEntry(
                    kind=det.kind,
                    start=det.start,
                    end=det.end,
                    value_hash=_hash(det.value),
                    placeholder=placeholder,
                    confidence=det.confidence,
                )
            )
            cursor = det.end
        parts.append(text[cursor:])
        return "".join(parts), log


def redact(text: str, placeholders: dict[str, str] | None = None) -> tuple[str, RedactionLog]:
    """Convenience wrapper: redact text in one call."""
    return Redactor(placeholders).redact(text)
