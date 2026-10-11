"""Data validation helper functions.

Stateless validators that return booleans — suitable for use in
guards, filters, and configuration checks.
"""

import re

# Pre-compiled patterns for performance
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

_HOSTNAME_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_ipv4(address: str) -> bool:
    """Check whether *address* is a valid IPv4 address.

    Args:
        address: The string to validate.

    Returns:
        ``True`` if *address* is a valid dotted-quad IPv4 address.
    """
    return bool(_IPV4_PATTERN.match(address))


def is_valid_port(port: int) -> bool:
    """Check whether *port* is within the valid TCP/UDP range.

    Args:
        port: The port number.

    Returns:
        ``True`` if ``1 <= port <= 65535``.
    """
    return isinstance(port, int) and 1 <= port <= 65535


def is_valid_hostname(hostname: str) -> bool:
    """Check whether *hostname* is a syntactically valid DNS hostname.

    Args:
        hostname: The hostname string.

    Returns:
        ``True`` if *hostname* conforms to RFC-952/1123 rules.
    """
    if not hostname or len(hostname) > 253:
        return False
    return bool(_HOSTNAME_PATTERN.match(hostname))


def is_non_empty_string(value: object) -> bool:
    """Check whether *value* is a non-empty, non-whitespace string.

    Args:
        value: The value to check.

    Returns:
        ``True`` if *value* is a ``str`` with at least one non-whitespace character.
    """
    return isinstance(value, str) and bool(value.strip())
