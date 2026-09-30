# Detectors

`pii-redactor` ships nine detectors. All are regex + heuristic: no model
weights, no network calls, so they run anywhere a pipeline runs.

| Kind          | What it catches                              | Heuristic                              | Confidence |
|---------------|----------------------------------------------|----------------------------------------|------------|
| `email`       | `user@domain.tld`                            | RFC-ish local/domain pattern           | 1.0        |
| `phone`       | US 10/11-digit, `+1`, separators ` - . ()`   | Rejects digit-runs (SSN/card overlap)  | 1.0        |
| `ssn`         | `\d{3}-\d{2}-\d{4}`                          | Rejects `000`, `666`, `900-999` areas  | 0.95       |
| `credit_card` | 13-19 digits with ` -` separators            | Luhn checksum must pass                | 0.9        |
| `api_key`     | AWS, GitHub, Stripe, OpenAI, Slack keys; labeled `api_key = ...` secrets | Provider patterns; labeled secrets must mix letters and digits | 0.85 / 0.75 |
| `mac_address` | `00:1A:2B:3C:4D:5E`                          | Six hex octets                         | 0.8        |
| `ip`          | IPv4 dotted quad                             | Octets must be 0-255                   | 0.7        |
| `ipv6`        | Full and compressed IPv6                     | Validated with `ipaddress`             | 0.7        |
| `dob`         | Date of birth, e.g. `DOB: 01/02/1990`        | Only when an explicit label precedes it | 0.6       |

## Overlap resolution

Detectors run independently, then `detect_all()` merges spans
deterministically:

1. Sort by start offset; longer spans win at the same offset.
2. Priority order breaks ties: API key, SSN, credit card, phone, email,
   IPv6, IP, MAC address, DOB.
3. Any span overlapping an accepted span is dropped.

This keeps output stable across runs: the same input always yields the
same spans, which matters when audit logs are compared across pipeline runs.

## Redaction strategies

| Strategy | Output for `jane@example.com` | Preserves | Use when |
|---|---|---|---|
| `placeholder` (default) | `[EMAIL]` | entity kind only | simplest scrub; logs stay clean |
| `mask` | `j***@example.com` | shape (domain, last-4) | debugging needs structure, not values |
| `hash` | `sha256:86e0b9e56c17` | deterministic join key | correlating redacted datasets |
| `tokenize` | `[EMAIL_1]` | per-value identity | readable logs; same value, same token |

```python
from pii_redactor import redact

redacted, log = redact(text, strategy="mask")
```

CLI: `pii-redact scan --input notes.txt --redact --strategy hash`.

The `hash` strategy is deterministic per value (same input, same hash,
across runs), so redacted datasets can still be joined. `tokenize` is
consistent within one `Redactor` instance. Both keep raw values out of the
output and the audit log.

## Streaming

For unbounded input (log streams, socket frames), `StreamRedactor` redacts
chunk by chunk without buffering everything:

```python
from pii_redactor.streaming import StreamRedactor

streamer = StreamRedactor(strategy="mask")
for chunk in log_stream:
    emit(streamer.feed(chunk))
emit(streamer.flush())
print(streamer.log.counts())  # absolute stream offsets in the audit log
```

A 256-char tail is held back at each chunk boundary so entities split
across chunks are still caught. Streamed output is byte-identical to batch
`redact()` on the same input; the audit log uses absolute offsets into the
full stream.

## Precision notes

Honest accounting of what each detector gets wrong:

- **Email**: high precision on standard addresses; will also match
  non-personal addresses (`noreply@`, `support@`) and version-like strings
  in rare cases. It cannot tell a personal email from a role account.
- **Phone**: tuned for US formats. International numbers are missed, and
  dense digit runs in prose can false-positive despite the digit-run guard.
- **SSN**: the area/group guards remove the obvious non-SSNs, but any
  `\d{3}-\d{2}-\d{4}` with a plausible area still matches, including
  non-SSN identifiers in that shape.
- **Credit card**: the Luhn requirement keeps precision high, but order
  numbers and other 13-19 digit runs occasionally pass Luhn by chance
  (roughly 1 in 10 random runs). Treat `confidence=0.9`, not certainty.
- **API key**: provider patterns are precise; the labeled generic pattern
  trades recall for precision by requiring a label (`api_key =`, `secret:`)
  and a letter+digit mix. Unlabeled secrets in prose are missed. This is
  deliberate: an unlabeled hex blob detector would false-positive on
  hashes, UUIDs, and commit SHAs constantly.
- **IP / IPv6 / MAC**: validated structurally, but any structurally valid
  address matches, including documentation ranges (`203.0.113.x`) and
  loopback. Filter reserved ranges downstream if that matters.
- **DOB**: only fires on explicitly labeled dates, which keeps precision
  high at the cost of recall. Unlabeled birthdays are not PII-shaped enough
  to catch safely with regex.

General limits (stated plainly):

- US-centric phone/SSN formats; international identifiers are not covered.
- Regex detectors trade recall for determinism: they will miss obfuscated
  PII (`jane [at] example [dot] com`) and can false-positive on digit-heavy
  prose. For high-stakes scrubbing, pair with a model-based detector and
  human review.

## Customizing

- **Placeholders**: pass `{"email": "<EMAIL>"}` to `Redactor` / `redact()`.
- **Strategies**: `Redactor(strategy="mask" | "hash" | "tokenize")`, or
  `redact(text, strategy=...)`.
- **New detectors**: write a function `(str) -> list[Detection]` and add it
  to the priority list in `detectors.py`.
- **Thresholds**: filter `detect_all()` output by `confidence` before
  redacting if you want a precision/recall knob.
