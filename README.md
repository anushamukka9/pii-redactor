# pii-redactor

**PII detection and redaction for AI pipelines — regex + heuristic detectors with span-level audit.**

Scrub emails, phones, SSNs, credit cards, and IPs from training data, logs,
and prompts *before* they reach a model — with an audit log that proves what
was removed without retaining the PII itself.

## Why

PII leaks into AI pipelines constantly: support tickets become fine-tuning
data, logs become eval sets, user prompts get logged verbatim. `pii-redactor`
gives you a deterministic, dependency-light scrub step that runs in CI, batch
ETL, or a pre-training gate — and produces a span-level audit trail so
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
print(log.to_dict())   # audit: kinds, spans, sha256 hashes — never raw PII
```

CLI:

```bash
# Scan a file; exit 2 when PII is found (handy as a CI gate)
pii-redact scan --input notes.txt

# Redact and write a JSON audit log
pii-redact scan --input notes.txt --redact --audit audit.json

# Machine-readable output
pii-redact scan --input notes.txt --format json
```

See [`examples/quickstart.py`](examples/quickstart.py).

## What it detects

| Kind | Example | Notes |
|------|---------|-------|
| Email | `jane.doe@example.com` | — |
| Phone | `+1 (415) 555-0132` | US formats; avoids SSN/card digit runs |
| SSN | `078-05-1120` | Rejects `000`/`666`/`900–999` areas |
| Credit card | `4111 1111 1111 1111` | Luhn checksum required |
| IP | `203.0.113.42` | IPv4, octets validated |

Full detector notes, overlap rules, and limitations: [`docs/DETECTORS.md`](docs/DETECTORS.md).

## Audit, not just redaction

Every redaction is recorded as `{kind, span, sha256(value)[:16], placeholder,
confidence}`. The raw value never lands in the log — you can prove *what*
was scrubbed and *where*, without keeping the PII around to prove it.

## CI gate

```yaml
- name: PII gate
  run: |
    pip install pii-redactor
    pii-redact scan --input training_data.txt --redact --audit pii-audit.json
```

Exit code `2` fails the build when PII is detected.

## License

MIT — see [LICENSE](LICENSE).
