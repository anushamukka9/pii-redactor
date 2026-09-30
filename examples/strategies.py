"""Redaction strategies: placeholder, mask, hash, tokenize.

The same input redacted four ways, showing what each strategy preserves and
what it hides. Run: python examples/strategies.py
"""

from pii_redactor import redact

TEXT = "Contact jane.doe@example.com or +1 (415) 555-0132 about card 4111 1111 1111 1111."

for strategy in ("placeholder", "mask", "hash", "tokenize"):
    redacted, log = redact(TEXT, strategy=strategy)
    print(f"--- {strategy} ---")
    print(redacted)
    print(f"counts: {log.counts()}\n")

print("Notes:")
print("- placeholder: simplest; downstream sees only the entity kind.")
print("- mask: keeps shape (domain, last-4) for debugging without the value.")
print("- hash: deterministic per value; joins across redacted datasets still work.")
print("- tokenize: consistent per-value tokens, readable in logs.")
