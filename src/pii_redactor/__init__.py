"""pii-redactor: PII detection and redaction for AI pipelines."""

from .detectors import Detection, detect_all, detect_credit_cards, detect_email, detect_ip, detect_phone, detect_ssn
from .redactor import RedactionLog, Redactor, redact

__all__ = [
    "Detection",
    "detect_all",
    "detect_credit_cards",
    "detect_email",
    "detect_ip",
    "detect_phone",
    "detect_ssn",
    "RedactionLog",
    "Redactor",
    "redact",
]
__version__ = "0.1.0"
