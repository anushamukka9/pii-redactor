"""CLI: pii-redact scan --input ..."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .detectors import detect_all
from .redactor import Redactor


@click.group()
def main() -> None:
    """PII detection and redaction for AI pipelines."""


@main.command("scan")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True),
              help="Text file to scan.")
@click.option("--redact", "do_redact", is_flag=True, default=False,
              help="Also emit the redacted text.")
@click.option("--audit", "audit_path", type=click.Path(), default=None,
              help="Write the JSON audit log to this file.")
@click.option("--format", "out_format", type=click.Choice(["text", "json"]), default="text")
def scan(input_path: str, do_redact: bool, audit_path: str | None, out_format: str) -> None:
    """Scan a file for PII; optionally redact and write an audit log."""
    text = Path(input_path).read_text(encoding="utf-8")
    detections = detect_all(text)

    redacted: str | None = None
    log = None
    if do_redact or audit_path:
        redacted, log = Redactor().redact(text)

    if audit_path and log is not None:
        Path(audit_path).write_text(json.dumps(log.to_dict(), indent=2), encoding="utf-8")

    if out_format == "json":
        payload = {
            "detections": [
                {
                    "kind": d.kind,
                    "span": [d.start, d.end],
                    "value": d.value,
                    "confidence": d.confidence,
                }
                for d in detections
            ],
            "redacted": redacted,
            "audit": log.to_dict() if log else None,
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        if not detections:
            click.echo("No PII detected.")
        for d in detections:
            click.echo(f"[{d.kind}] @{d.start}-{d.end}: {d.value!r} (conf={d.confidence})")
        if do_redact and redacted is not None:
            click.echo("\n--- redacted ---")
            click.echo(redacted)

    # Exit 2 when PII was found (useful as a CI gate); 0 when clean.
    sys.exit(2 if detections else 0)


if __name__ == "__main__":
    main()
