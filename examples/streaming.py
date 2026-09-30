"""Streaming redaction: redact a large input chunk by chunk.

Simulates a log stream where entities can straddle chunk boundaries.
The streamed output is identical to batch redaction, and the audit log
keeps absolute offsets into the full stream.
Run: python examples/streaming.py
"""

from pii_redactor import redact
from pii_redactor.streaming import StreamRedactor

LINES = [
    "2026-09-29 user jane.doe@example.com logged in from 203.0.113.42\n",
    "2026-09-29 payment card 4111 1111 1111 1111 approved for +1 (415) 555-0132\n",
    "2026-09-29 api key AKIAIOSFODNN7EXAMPLE rotated; DOB: 01/02/1990 on file\n",
]

# Feed in awkward 37-char chunks so entities straddle boundaries.
streamer = StreamRedactor(strategy="mask")
blob = "".join(LINES)
out = "".join(streamer.feed(blob[i:i + 37]) for i in range(0, len(blob), 37))
out += streamer.flush()

print("== streamed (mask) ==")
print(out)

expected, _ = redact(blob, strategy="mask")
assert out == expected, "streaming diverged from batch redaction"
print("streamed output matches batch redaction:", out == expected)

print("\n== audit ==")
print(streamer.log.counts())
for e in streamer.log.entries:
    print(f"[{e.kind}] span={e.start}-{e.end} -> {e.placeholder}")
