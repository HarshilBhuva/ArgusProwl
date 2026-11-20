"""Shared resource limits for untrusted collector records."""

MAX_RAW_RECORD_BYTES = 10 * 1024 * 1024


def exceeds_raw_record_limit(value: str) -> bool:
    """Return whether a text record exceeds the UTF-8 byte budget.

    Check the character count first so obviously oversized inputs do not incur
    an additional full-size UTF-8 allocation.
    """
    if len(value) > MAX_RAW_RECORD_BYTES:
        return True
    return len(value.encode("utf-8")) > MAX_RAW_RECORD_BYTES
