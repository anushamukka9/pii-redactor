# Detectors

`pii-redactor` ships five detectors. All are regex + heuristic — no model
weights, no network calls — so they run anywhere a pipeline runs.

| Kind          | What it catches                              | Heuristic                              | Confidence |
|---------------|----------------------------------------------|----------------------------------------|------------|
| `email`       | `user@domain.tld`                            | RFC-ish local/domain pattern           | 1.0        |
| `phone`       | US 10/11-digit, `+1`, separators ` - . ()`   | Rejects digit-runs (SSN/card overlap)  | 1.0        |
| `ssn`         | `\d{3}-\d{2}-\d{4}`                          | Rejects `000`, `666`, `900–999` areas  | 0.95       |
| `credit_card` | 13–19 digits with ` -` separators            | Luhn checksum must pass                | 0.9        |
| `ip`          | IPv4 dotted quad                             | Octets must be 0–255                   | 0.7        |

## Overlap resolution

Detectors run independently, then `detect_all()` merges spans
deterministically:

1. Sort by start offset; longer spans win at the same offset.
2. Priority order breaks ties: SSN → credit card → phone → email → IP.
3. Any span overlapping an accepted span is dropped.

This keeps output stable across runs — the same input always yields the
same spans, which matters when audit logs are compared across pipeline runs.

## Customizing

- **Placeholders**: pass `{"email": "<EMAIL>"}` to `Redactor` / `redact()`.
- **New detectors**: write a function `(str) -> list[Detection]` and add it to
  the priority list in `detectors.py`.
- **Thresholds**: filter `detect_all()` output by `confidence` before
  redacting if you want a precision/recall knob.

## Limitations (stated plainly)

- US-centric phone/SSN formats; international identifiers are not covered.
- Regex detectors trade recall for determinism — they will miss obfuscated
  PII (`jane [at] example [dot] com`) and can false-positive on digit-heavy
  prose. For high-stakes scrubbing, pair with a model-based detector and
  human review.
