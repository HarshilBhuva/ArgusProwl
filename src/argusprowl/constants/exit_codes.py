"""Process exit code constants.

Provides meaningful exit codes for CLI and application termination.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Standard process exit codes for the argusprowl CLI."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    CONFIG_ERROR = 2
    RUNTIME_ERROR = 3
    PERMISSION_ERROR = 4
    KEYBOARD_INTERRUPT = 130
