"""Redaction with a span-level audit trail.

The :class:`Redactor` replaces detected spans according to a configurable
strategy and records every replacement in a :class:`RedactionLog`: which
original value (hashed, never stored raw), where it was, and what replaced
it. The audit log is what makes this pipeline-grade: you can prove what was
scrubbed, without keeping the PII.

Strategies:

- ``placeholder`` (default): ``jane@example.com`` becomes ``[EMAIL]``.
- ``mask``: keep non-identifying structure, hide the rest
  (``j***@example.com``, ``***-**-1120``). Useful when downstream tooling
  needs the shape of the data (domain, last-4) but not the value.
- ``hash``: deterministic ``sha256:<12 hex chars>`` per value. The same
  value always maps to the same hash, so joins across redacted datasets
  still work without ever storing PII.
- ``tokenize``: consistent per-value tokens (``[EMAIL_1]``, ``[EMAIL_2]``)
  within one :class:`Redactor` instance. Readable in logs; reversible only
  by whoever holds the original text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .detectors import Detection, detect_all

PLACEHOLDERS: dict[str, str] = {
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "ssn": "[SSN]",
    "credit_card": "[CREDIT_CARD]",
    "ip": "[IP]",
    "ipv6": "[IPV6]",
    "mac_address": "[MAC_ADDRESS]",
    "api_key": "[API_KEY]",
    "dob": "[DOB]",
}

STRATEGIES = ("placeholder", "mask", "hash", "tokenize")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def mask_value(kind: str, value: str) -> str:
    """Partially mask a detected value, keeping non-identifying structure."""
    if kind == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}" if domain else "***"
    if kind == "phone":
        return f"***-***-{_digits(value)[-4:]}"
    if kind == "ssn":
        return f"***-**-{_digits(value)[-4:]}"
    if kind == "credit_card":
        return f"****-****-****-{_digits(value)[-4:]}"
    if kind == "ip":
        octets = value.split(".")
        return ".".join(octets[:3] + ["***"]) if len(octets) == 4 else "***.***.***.***"
    if kind == "api_key":
        return f"{value[:4]}****{value[-4:]}" if len(value) > 8 else "********"
    # ipv6, mac_address, dob: keep a short tail so rows stay distinguishable.
    return f"***{value[-4:]}"


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
    strategy: str = "placeholder"

    def counts(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for e in self.entries:
            totals[e.kind] = totals.get(e.kind, 0) + 1
        return totals

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
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
    """Redact PII spans with a chosen strategy, keeping an audit log."""

    def __init__(
        self,
        placeholders: dict[str, str] | None = None,
        strategy: str = "placeholder",
    ):
        if strategy not in STRATEGIES:
            raise ValueError(f"strategy must be one of {STRATEGIES}, got {strategy!r}")
        self.placeholders = {**PLACEHOLDERS, **(placeholders or {})}
        self.strategy = strategy
        self._token_counters: dict[str, int] = {}
        self._token_map: dict[str, str] = {}

    # -- strategy rendering -------------------------------------------------
    def _token_for(self, kind: str, value: str) -> str:
        if value not in self._token_map:
            self._token_counters[kind] = self._token_counters.get(kind, 0) + 1
            self._token_map[value] = f"[{kind.upper()}_{self._token_counters[kind]}]"
        return self._token_map[value]

    def render_replacement(self, detection: Detection) -> str:
        """The replacement string for one detection under this strategy."""
        if self.strategy == "mask":
            return mask_value(detection.kind, detection.value)
        if self.strategy == "hash":
            return f"sha256:{_hash(detection.value)[:12]}"
        if self.strategy == "tokenize":
            return self._token_for(detection.kind, detection.value)
        return self.placeholders.get(detection.kind, "[REDACTED]")

    # -- redaction ----------------------------------------------------------
    def _apply(
        self, text: str, detections: list[Detection], offset: int = 0
    ) -> tuple[str, list[RedactionEntry]]:
        """Redact ``detections`` (sorted, non-overlapping) from ``text``.

        ``offset`` shifts the recorded spans; used by the streaming redactor
        so audit spans stay absolute across chunks.
        """
        parts: list[str] = []
        entries: list[RedactionEntry] = []
        cursor = 0
        for det in detections:
            parts.append(text[cursor:det.start])
            replacement = self.render_replacement(det)
            parts.append(replacement)
            entries.append(
                RedactionEntry(
                    kind=det.kind,
                    start=offset + det.start,
                    end=offset + det.end,
                    value_hash=_hash(det.value),
                    placeholder=replacement,
                    confidence=det.confidence,
                )
            )
            cursor = det.end
        parts.append(text[cursor:])
        return "".join(parts), entries

    def redact(self, text: str) -> tuple[str, RedactionLog]:
        detections = detect_all(text)
        log = RedactionLog(strategy=self.strategy)
        if not detections:
            return text, log
        redacted, entries = self._apply(text, detections)
        log.entries.extend(entries)
        return redacted, log


def redact(
    text: str,
    placeholders: dict[str, str] | None = None,
    strategy: str = "placeholder",
) -> tuple[str, RedactionLog]:
    """Convenience wrapper: redact text in one call."""
    return Redactor(placeholders, strategy).redact(text)
