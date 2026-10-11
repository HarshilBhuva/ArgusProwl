"""JSON file alert provider.

Writes alerts to JSON files for structured logging and integration
with external systems.
"""

import json
import os
from pathlib import Path
from typing import Any

from argusprowl.interfaces.alert_provider import AlertProvider
from argusprowl.models.alert import Alert


class JsonAlertProvider(AlertProvider):
    """Writes alerts to JSON files.

    Appends alerts to a JSON lines file for structured logging
    and downstream processing.

    Attributes:
        provider_name: Provider identifier.
        output_path: Path to output JSON file.
        pretty_print: Whether to format JSON with indentation.
    """

    def __init__(
        self,
        output_path: str | Path = "reports/alerts.jsonl",
        pretty_print: bool = False,
    ) -> None:
        """Initialize JSON alert provider.

        Args:
            output_path: Path to output JSON file.
            pretty_print: Whether to format JSON with indentation.
        """
        self._provider_name = "json"
        self._output_path = Path(output_path)
        self._pretty_print = pretty_print
        self._available = True

        # Ensure output directory exists
        self._output_path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> bool:
        """Write alert to JSON file.

        Args:
            alert: Alert to write.

        Returns:
            True if alert was written successfully.
        """
        try:
            # Convert alert to dictionary
            alert_dict = self._alert_to_dict(alert)

            # Append to file as JSON line
            with open(self._output_path, "a", encoding="utf-8") as f:
                json_line = json.dumps(alert_dict, ensure_ascii=False)
                f.write(json_line + "\n")

            return True

        except Exception as exc:
            print(f"Error writing alert to JSON file: {exc}")
            return False

    def is_available(self) -> bool:
        """Check if output file is writable.

        Returns:
            True if file is writable, False otherwise.
        """
        try:
            # Try to check if we can write to the file
            if not self._output_path.parent.exists():
                return False

            # If file exists, check if writable
            if self._output_path.exists():
                return os.access(self._output_path, os.W_OK)

            # If file doesn't exist, try to create it
            with open(self._output_path, "a"):
                pass
            return True

        except Exception:
            return False

    def _alert_to_dict(self, alert: Alert) -> dict[str, Any]:
        """Convert Alert to dictionary for JSON serialization.

        Args:
            alert: Alert to convert.

        Returns:
            Dictionary representation of alert.
        """
        return alert.to_dict()

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return self._provider_name

    @property
    def output_path(self) -> Path:
        """Get output file path."""
        return self._output_path

    def __repr__(self) -> str:
        """String representation."""
        return f"JsonAlertProvider(path={self._output_path})"
