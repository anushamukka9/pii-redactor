"""Quickstart: detect and redact PII in a sample document."""

from pii_redactor import detect_all, redact

SAMPLE = """\
Contact Jane Doe at jane.doe@example.com or +1 (415) 555-0132.
SSN on file: 078-05-1120. Card used: 4111 1111 1111 1111.
Request originated from 203.0.113.42.
"""

print("== detections ==")
for d in detect_all(SAMPLE):
    print(f"[{d.kind}] {d.value!r} @{d.start}-{d.end}")

redacted, log = redact(SAMPLE)
print("\n== redacted ==")
print(redacted)
print("\n== audit counts ==", log.counts())
