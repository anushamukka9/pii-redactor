# pii-redactor

**PII detection and redaction for AI pipelines: regex plus heuristic detectors with span-level audit.**

Scrub emails, phones, SSNs, credit cards, API keys, IPs, MAC addresses, and
dates of birth from training data, logs, and prompts *before* they reach a
model, with an audit log that proves what was removed without retaining the
PII itself.

## Why

PII leaks into AI pipelines constantly: support tickets become fine-tuning
data, logs become eval sets, user prompts get logged verbatim. `pii-redactor`
gives you a deterministic, dependency-light scrub step that runs in CI, batch
ETL, or a pre-training gate, and produces a span-level audit trail so
compliance can verify the scrub without ever seeing the raw values.

## Install

```bash
pip install pii-redactor
```

Or from source:

```bash
git clone https://github.com/anushamukka9/pii-redactor
cd pii-redactor
pip install -e ".[dev]"
```

## Quickstart

```python
from pii_redactor import detect_all, redact

text = "Contact jane.doe@example.com or +1 (415) 555-0132."

for d in detect_all(text):
    print(d.kind, d.value, (d.start, d.end))

redacted, log = redact(text)
print(redacted)        # Contact [EMAIL] or [PHONE].
print(log.counts())    # {'email': 1, 'phone': 1}
print(log.to_dict())   # audit: kinds, spans, sha256 hashes, never raw PII
```

CLI:

```bash
# Scan a file; exit 2 when PII is found (handy as a CI gate)
pii-redact scan --input notes.txt

# Redact with the mask strategy and write a JSON audit log
pii-redact scan --input notes.txt --redact --strategy mask --audit audit.json

# Machine-readable output
pii-redact scan --input notes.txt --format json
```

See `examples/`: `quickstart.py`, `strategies.py`, `streaming.py`.

## What it detects

| Kind | Example | Notes |
|------|---------|-------|
| Email | `jane.doe@example.com` | |
| Phone | `+1 (415) 555-0132` | US formats; avoids SSN/card digit runs |
| SSN | `078-05-1120` | Rejects `000`/`666`/`900-999` areas |
| Credit card | `4111 1111 1111 1111` | Luhn checksum required |
| API key | `AKIA...`, `ghp_...`, `sk-...` | AWS, GitHub, Stripe, OpenAI, Slack + labeled secrets |
| IP | `203.0.113.42` | IPv4, octets validated |
| IPv6 | `2001:db8::1` | Validated with `ipaddress` |
| MAC address | `00:1A:2B:3C:4D:5E` | |
| Date of birth | `DOB: 01/02/1990` | Only when explicitly labeled |

Full detector notes, overlap rules, strategies, and precision notes:
[`docs/DETECTORS.md`](docs/DETECTORS.md).

## Redaction strategies

| Strategy | Example output | Best for |
|---|---|---|
| `placeholder` (default) | `[EMAIL]` | Simple scrubbing |
| `mask` | `j***@example.com` | Debugging with structure, not values |
| `hash` | `sha256:86e0b9e56c17` | Deterministic joins across redacted datasets |
| `tokenize` | `[EMAIL_1]` | Readable logs; same value always gets the same token |

```python
redacted, log = redact(text, strategy="mask")
```

## Streaming

Redact unbounded input chunk by chunk; output is byte-identical to batch
redaction, and the audit log keeps absolute stream offsets:

```python
from pii_redactor.streaming import StreamRedactor

streamer = StreamRedactor(strategy="mask")
for chunk in log_stream:
    emit(streamer.feed(chunk))
emit(streamer.flush())
```

## Audit, not just redaction

Every redaction is recorded as `{kind, span, sha256(value)[:16], placeholder,
confidence}`. The raw value never lands in the log: you can prove *what*
was scrubbed and *where*, without keeping the PII around to prove it.

## API reference

| Piece | Description |
|---|---|
| `detect_all(text)` | All detectors, overlaps resolved, sorted by offset |
| `detect_email/phone/ssn/credit_cards/ip/ipv6/mac_address/dob/api_keys` | Individual detectors |
| `redact(text, strategy=...)` | Redact in one call; returns `(text, RedactionLog)` |
| `Redactor(placeholders, strategy)` | Reusable redactor; `tokenize` stays consistent per instance |
| `mask_value(kind, value)` | The partial-masking rule per entity kind |
| `StreamRedactor(**kwargs)` | `feed(chunk)` / `flush()` / `.log` for streaming |
| `redact_stream(chunks, **kwargs)` | One-shot streaming generator |
| `RedactionLog.counts()` / `.to_dict()` | Counts per kind; JSON-serializable audit |

## CI gate

```yaml
- name: PII gate
  run: |
    pip install pii-redactor
    pii-redact scan --input training_data.txt --redact --audit pii-audit.json
```

Exit code `2` fails the build when PII is detected.

## Production notes

- Regex detectors trade recall for determinism. They miss obfuscated PII
  and international formats; for high-stakes scrubbing, pair with a
  model-based detector and human review. Per-detector precision notes are in
  `docs/DETECTORS.md`.
- The audit log stores hashes, never raw values, but hashes of low-entropy
  PII (a phone number) are brute-forceable. Treat audit logs as sensitive.
- `hash`-strategy outputs are stable across runs, so they can serve as join
  keys; `tokenize` tokens are only consistent within one `Redactor`
  instance.

## License

MIT: see [LICENSE](LICENSE).
