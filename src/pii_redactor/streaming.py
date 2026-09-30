"""Streaming redaction for unbounded input.

:class:`StreamRedactor` redacts text chunk by chunk (log lines, socket
frames, file blocks) and emits redacted output incrementally, without
buffering the whole input. A short tail is held back from each chunk so
entities split across chunk boundaries are still caught; the audit log keeps
absolute offsets into the full input stream.

``redact_stream`` is the one-shot convenience wrapper::

    redacted_pieces = list(redact_stream(open("big.log"), strategy="mask"))
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .detectors import detect_all
from .redactor import RedactionLog, Redactor

# Chars held back at each chunk boundary. Must exceed the longest entity the
# detectors can match (API keys and labeled secrets are the longest).
TAIL_CHARS = 256


class StreamRedactor:
    """Incremental redactor: ``feed`` chunks in, get redacted text out."""

    def __init__(self, **redactor_kwargs):
        self._redactor = Redactor(**redactor_kwargs)
        self._pending = ""
        self._base = 0  # absolute offset of self._pending in the stream
        self._log = RedactionLog(strategy=self._redactor.strategy)

    @property
    def log(self) -> RedactionLog:
        """Audit log accumulated so far (absolute stream offsets)."""
        return self._log

    def feed(self, chunk: str) -> str:
        """Redact ``chunk``; returns the redacted text safe to emit now."""
        data = self._pending + chunk
        cut = max(0, len(data) - TAIL_CHARS)
        # Only redact detections fully inside the safe prefix; anything
        # touching the tail stays pending for the next chunk.
        detections = [d for d in detect_all(data) if d.end <= cut]
        redacted, entries = self._redactor._apply(data[:cut], detections, offset=self._base)
        self._log.entries.extend(entries)
        self._pending = data[cut:]
        self._base += cut
        return redacted

    def flush(self) -> str:
        """Redact and emit whatever is still buffered."""
        detections = detect_all(self._pending)
        redacted, entries = self._redactor._apply(
            self._pending, detections, offset=self._base
        )
        self._log.entries.extend(entries)
        self._base += len(self._pending)
        self._pending = ""
        return redacted


def redact_stream(
    chunks: Iterable[str], **redactor_kwargs
) -> Iterator[str]:
    """Yield redacted text for each input chunk, then the final flush."""
    streamer = StreamRedactor(**redactor_kwargs)
    for chunk in chunks:
        yield streamer.feed(chunk)
    yield streamer.flush()
