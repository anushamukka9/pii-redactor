"""Tests for new detectors, redaction strategies, and streaming."""

from pii_redactor.detectors import (
    detect_all,
    detect_api_keys,
    detect_dob,
    detect_ipv6,
    detect_mac_address,
)
from pii_redactor.redactor import Redactor, mask_value, redact
from pii_redactor.streaming import StreamRedactor, redact_stream

# --- new detectors --------------------------------------------------------

def test_detect_api_keys_providers():
    cases = [
        "key AKIAIOSFODNN7EXAMPLE here",
        "token ghp_abcdefghijklmnopqrstuvwxyz1234567890 here",
        "key sk-abcdefABCDEF1234567890XY here",
        "stripe rk_live_abcDEF1234567890xyz here",
        "openai sk-proj-abcdefghijklmnopqrstuvwxyz1234 here",
    ]
    for text in cases:
        dets = detect_api_keys(text)
        assert len(dets) == 1, text
        assert dets[0].kind == "api_key"
        assert dets[0].detail.startswith("provider=")


def test_detect_api_keys_labeled_generic():
    dets = detect_api_keys('config: api_key = "s3cr3tValue99XYZabc"')
    assert len(dets) == 1
    assert dets[0].value == "s3cr3tValue99XYZabc"
    assert dets[0].detail == "labeled generic secret"
    # Plain words after a label are not secrets (letter+digit heuristic).
    assert detect_api_keys("password = hunter") == []
    assert detect_api_keys("token = abcdefghijklmnop") == []


def test_detect_ipv6():
    dets = detect_ipv6("client 2001:db8::1 connected")
    assert len(dets) == 1
    assert dets[0].kind == "ipv6"
    assert dets[0].value == "2001:db8::1"
    assert detect_ipv6("not an ip: zzzz::1") == []


def test_detect_mac_address():
    dets = detect_mac_address("device 00:1A:2B:3C:4D:5E seen")
    assert len(dets) == 1
    assert dets[0].kind == "mac_address"
    assert dets[0].value == "00:1A:2B:3C:4D:5E"


def test_detect_dob_labeled_only():
    dets = detect_dob("Patient DOB: 01/02/1990 admitted")
    assert len(dets) == 1
    assert dets[0].kind == "dob"
    assert dets[0].value == "01/02/1990"
    # Unlabeled dates are not flagged (precision choice).
    assert detect_dob("the meeting is on 01/02/1990") == []
    assert detect_dob("DOB: 13/45/1990") == []


def test_detect_all_includes_new_kinds():
    text = "key AKIAIOSFODNN7EXAMPLE from 2001:db8::1 (00:1A:2B:3C:4D:5E)"
    kinds = {d.kind for d in detect_all(text)}
    assert {"api_key", "ipv6", "mac_address"} <= kinds


# --- strategies -----------------------------------------------------------

def test_mask_strategy_shapes():
    assert mask_value("email", "jane.doe@example.com") == "j***@example.com"
    assert mask_value("ssn", "078-05-1120") == "***-**-1120"
    assert mask_value("credit_card", "4111 1111 1111 1111") == "****-****-****-1111"
    assert mask_value("ip", "203.0.113.42") == "203.0.113.***"
    assert mask_value("phone", "+1 (415) 555-0132") == "***-***-0132"


def test_mask_strategy_end_to_end():
    redacted, log = redact("mail jane@example.com ssn 078-05-1120", strategy="mask")
    assert "j***@example.com" in redacted
    assert "***-**-1120" in redacted
    assert "jane@example.com" not in redacted
    assert log.strategy == "mask"
    assert log.to_dict()["strategy"] == "mask"


def test_hash_strategy_deterministic():
    r1, _ = redact("a jane@example.com b jane@example.com", strategy="hash")
    assert r1.count("sha256:") == 2
    first, second = r1.split(" b ")
    assert first.split("a ")[1] == second  # same value -> same hash
    r2, _ = redact("a jane@example.com", strategy="hash")
    assert r2.split("a ")[1] == first.split("a ")[1]  # stable across runs
    assert "jane@example.com" not in r1


def test_tokenize_strategy_consistent_per_value():
    redacted, _ = redact(
        "a jane@example.com b bob@example.com c jane@example.com", strategy="tokenize"
    )
    assert redacted == "a [EMAIL_1] b [EMAIL_2] c [EMAIL_1]"


def test_invalid_strategy_rejected():
    try:
        Redactor(strategy="rot13")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_default_strategy_unchanged():
    redacted, log = redact("ping jane@example.com")
    assert "[EMAIL]" in redacted
    assert log.strategy == "placeholder"


# --- streaming ------------------------------------------------------------

STREAM_TEXT = (
    "Contact jane.doe@example.com or +1 (415) 555-0132. "
    "SSN 078-05-1120, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE. "
    "From 2001:db8::1 at 203.0.113.42. DOB: 01/02/1990."
)


def _chunks(text: str, size: int):
    return [text[i:i + size] for i in range(0, len(text), size)]


def test_streaming_matches_batch():
    expected, _ = redact(STREAM_TEXT)
    for size in (1, 7, 40, 200, 10000):
        got = "".join(redact_stream(_chunks(STREAM_TEXT, size)))
        assert got == expected, f"chunk size {size}"


def test_streaming_matches_batch_for_all_strategies():
    for strategy in ("placeholder", "mask", "hash", "tokenize"):
        expected, _ = redact(STREAM_TEXT, strategy=strategy)
        got = "".join(redact_stream(_chunks(STREAM_TEXT, 23), strategy=strategy))
        assert got == expected, strategy


def test_streaming_log_offsets_absolute():
    streamer = StreamRedactor()
    pieces = [streamer.feed(c) for c in _chunks(STREAM_TEXT, 30)]
    pieces.append(streamer.flush())
    batch_log = redact(STREAM_TEXT)[1]
    assert "".join(pieces) == redact(STREAM_TEXT)[0]
    streamed = {(e.kind, e.start, e.end) for e in streamer.log.entries}
    batched = {(e.kind, e.start, e.end) for e in batch_log.entries}
    assert streamed == batched


def test_streaming_split_entity_across_chunks():
    # Split right in the middle of the email address.
    idx = STREAM_TEXT.index("jane.doe@example.com") + 8
    chunks = [STREAM_TEXT[:idx], STREAM_TEXT[idx:]]
    got = "".join(redact_stream(chunks))
    expected, _ = redact(STREAM_TEXT)
    assert got == expected
