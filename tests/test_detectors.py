"""Tests for PII detectors and the redactor."""

from pii_redactor.detectors import (
    detect_all,
    detect_credit_cards,
    detect_email,
    detect_ip,
    detect_phone,
    detect_ssn,
    luhn_valid,
)
from pii_redactor.redactor import Redactor, redact


def test_detect_email():
    dets = detect_email("reach me at jane.doe@example.com please")
    assert len(dets) == 1
    assert dets[0].kind == "email"
    assert dets[0].value == "jane.doe@example.com"


def test_detect_phone_formats():
    for number in ["+1 (415) 555-0132", "415-555-0132", "415.555.0132"]:
        dets = detect_phone(f"call {number} now")
        assert len(dets) == 1, number
        assert dets[0].kind == "phone"


def test_detect_ssn_rejects_invalid_area():
    # 666 and 900-series prefixes are not valid SSNs.
    assert detect_ssn("ssn 666-12-3456") == []
    assert detect_ssn("ssn 900-12-3456") == []
    dets = detect_ssn("ssn 078-05-1120")
    assert len(dets) == 1
    assert dets[0].kind == "ssn"


def test_luhn_and_credit_card():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    dets = detect_credit_cards("card 4111 1111 1111 1111 ok")
    assert len(dets) == 1
    assert dets[0].kind == "credit_card"
    # Random 16-digit run that fails Luhn is not flagged.
    assert detect_credit_cards("id 1234 5678 9012 3456") == []


def test_detect_ip():
    dets = detect_ip("from 203.0.113.42 yesterday")
    assert len(dets) == 1
    assert dets[0].value == "203.0.113.42"
    assert detect_ip("version 999.999.1.1") == []


def test_detect_all_resolves_overlaps():
    text = "ssn 078-05-1120 and jane@example.com"
    dets = detect_all(text)
    kinds = [d.kind for d in dets]
    assert "ssn" in kinds and "email" in kinds
    spans = sorted((d.start, d.end) for d in dets)
    for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
        assert e1 <= s2  # no overlaps


def test_redact_placeholders_and_audit():
    text = "email jane@example.com, phone 415-555-0132"
    redacted, log = redact(text)
    assert "[EMAIL]" in redacted
    assert "[PHONE]" in redacted
    assert "jane@example.com" not in redacted
    assert log.counts() == {"email": 1, "phone": 1}
    # Audit stores hashes, never raw values.
    raw_values = [e.value_hash for e in log.entries]
    assert all(len(h) == 16 for h in raw_values)
    assert not any("jane" in h for h in raw_values)


def test_redactor_custom_placeholders():
    r = Redactor(placeholders={"email": "<EMAIL_ADDRESS>"})
    redacted, _ = r.redact("ping jane@example.com")
    assert "<EMAIL_ADDRESS>" in redacted


def test_clean_text_passes_through():
    text = "The quick brown fox jumps over the lazy dog."
    redacted, log = redact(text)
    assert redacted == text
    assert log.entries == []
