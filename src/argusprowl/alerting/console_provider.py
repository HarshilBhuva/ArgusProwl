"""Console alert provider.

Displays alerts to the console with color-coded severity levels.
"""

import sys
from typing import Any, ClassVar

from argusprowl.interfaces.alert_provider import AlertProvider
from argusprowl.models.alert import Alert


class ConsoleAlertProvider(AlertProvider):
    """Displays alerts to the console.

    Formats and prints alerts with ANSI color coding based on severity.

    Attributes:
        provider_name: Provider identifier.
        use_colors: Whether to use ANSI color codes.
        include_timestamp: Whether to include timestamps in output.
    """

    # ANSI color codes
    COLORS: ClassVar[dict[str, str]] = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",  # Yellow
        "MEDIUM": "\033[94m",  # Blue
        "LOW": "\033[92m",  # Green
        "INFO": "\033[90m",  # Gray
        "RESET": "\033[0m",  # Reset
    }

    def __init__(
        self,
        use_colors: bool = True,
        include_timestamp: bool = True,
    ) -> None:
        """Initialize console alert provider.

        Args:
            use_colors: Whether to use ANSI color codes.
            include_timestamp: Whether to include timestamps.
        """
        self._provider_name = "console"
        self._use_colors = use_colors
        self._include_timestamp = include_timestamp
        self._available = True

    def send(self, alert: Alert) -> bool:
        """Display alert to console.

        Args:
            alert: Alert to display.

        Returns:
            True if alert was displayed successfully.
        """
        try:
            lines = []

            if self._include_timestamp:
                timestamp = alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                lines.append(f"[{timestamp}]")

            # Header: severity, title, rule
            severity_str = alert.severity.name
            if self._use_colors and sys.stdout.isatty():
                color = self.COLORS.get(severity_str, self.COLORS["RESET"])
                reset = self.COLORS["RESET"]
                lines.append(f"{color}[{severity_str}]{reset}")
            else:
                lines.append(f"[{severity_str}]")
            lines.append(f"Title: {alert.title}")
            lines.append(f"Rule: {alert.source}")
            lines.append(f"Alert ID: {alert.alert_id}")

            # Priority — separate from severity (operational ordering, not risk score)
            if alert.priority is not None:
                priority_str = alert.priority.value
                if self._use_colors and sys.stdout.isatty():
                    color = self.COLORS.get(priority_str, self.COLORS["RESET"])
                    reset = self.COLORS["RESET"]
                    lines.append(f"{color}Priority: {priority_str}{reset}")
                else:
                    lines.append(f"Priority: {priority_str}")

            if alert.tags:
                lines.append(f"Tags: {', '.join(alert.tags)}")

            # Confidence — keep detector and contextual separate
            if alert.detector_confidence is not None:
                lines.append(f"Detector confidence: {alert.detector_confidence:.2f}")
            if alert.contextual_confidence is not None:
                lines.append(f"Contextual confidence: {alert.contextual_confidence:.2f}")

            # Entity context — only non-None fields, in analyst-friendly order
            if alert.entity_context:
                ctx = alert.entity_context
                entity_lines: list[str] = []
                if ctx.get("host"):
                    entity_lines.append(f"Host: {ctx['host']}")
                if ctx.get("process_name"):
                    proc = ctx["process_name"]
                    pid = ctx.get("pid")
                    entity_lines.append(
                        f"Process: {proc}" + (f" (PID {pid})" if pid is not None else "")
                    )
                if ctx.get("username"):
                    entity_lines.append(f"Username: {ctx['username']}")
                if ctx.get("src_ip"):
                    entity_lines.append(f"Source IP: {ctx['src_ip']}")
                if ctx.get("dst_ip"):
                    dst = ctx["dst_ip"]
                    port = ctx.get("dst_port")
                    entity_lines.append(
                        f"Destination: {dst}" + (f":{port}" if port is not None else "")
                    )
                if ctx.get("domain"):
                    entity_lines.append(f"Domain: {ctx['domain']}")
                if entity_lines:
                    lines.extend(entity_lines)

            # WHY — contextual explanation
            if alert.contextual_explanation:
                lines.append("WHY:")
                lines.append(alert.contextual_explanation)

            # Supporting evidence
            if alert.supporting_evidence:
                lines.append("SUPPORTING EVIDENCE:")
                lines.extend(self._format_evidence_items(alert.supporting_evidence))

            # Contradictory evidence — always separate from supporting
            if alert.contradictory_evidence:
                lines.append("CONTRADICTORY EVIDENCE:")
                lines.extend(self._format_evidence_items(alert.contradictory_evidence))

            # Investigation pivots — numbered list
            if alert.investigation_pivots:
                lines.append("INVESTIGATION PIVOTS:")
                for idx, pivot in enumerate(alert.investigation_pivots, start=1):
                    lines.append(f"  {idx}. {pivot}")

            # Behavioral context — descriptive summary from entity behavior profile
            behavioral_summary = alert.metadata.get("behavioral_summary")
            if behavioral_summary:
                lines.append("BEHAVIORAL CONTEXT:")
                lines.extend(self._format_behavioral_summary(behavioral_summary))

            # Baseline evidence — explanatory context for classification decisions
            baseline_evidence = alert.metadata.get("baseline_evidence")
            if isinstance(baseline_evidence, dict):
                lines.append("BASELINE EVIDENCE:")
                lines.extend(self._format_baseline_evidence(baseline_evidence))

            # Legacy fallback: metadata confidence / evidence when no assessment fields
            if alert.metadata:
                confidence = alert.metadata.get("confidence")
                if confidence is not None and alert.detector_confidence is None:
                    lines.append(f"Confidence: {confidence:.2f}")
                evidence = alert.metadata.get("evidence")
                if evidence:
                    lines.append("EVIDENCE:")
                    lines.extend(self._format_evidence_items(evidence))

            print("\n".join(lines))
            print("-" * 80)
            return True

        except Exception as exc:
            print(f"Error displaying alert to console: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _format_behavioral_summary(summary: dict[str, Any]) -> list[str]:
        """Format behavioral summary for console display.

        Args:
            summary: Dictionary representation of EntityBehaviorSummary.

        Returns:
            List of formatted lines for console output.
        """
        lines: list[str] = []
        if not isinstance(summary, dict):
            return lines

        entity_type = summary.get("entity_type", "unknown")
        entity_id = summary.get("entity_id", "unknown")
        dimension = summary.get("dimension", "unknown")
        observation_count = summary.get("observation_count", 0)
        distinct_value_count = summary.get("distinct_value_count", 0)
        maturity = summary.get("maturity", "unknown")
        narrative = summary.get("narrative", "")
        top_values = summary.get("top_values", [])

        # Header line with entity and dimension
        lines.append(f"  Entity: {entity_type}/{entity_id} [{dimension}]")
        lines.append(
            f"  Observations: {observation_count} across {distinct_value_count} distinct values"
        )
        lines.append(f"  Maturity: {maturity}")

        # First/last seen
        first_seen = summary.get("first_seen")
        last_seen = summary.get("last_seen")
        if first_seen or last_seen:
            seen_parts = []
            if first_seen:
                seen_parts.append(f"first: {first_seen}")
            if last_seen:
                seen_parts.append(f"last: {last_seen}")
            if seen_parts:
                lines.append(f"  Window: {', '.join(seen_parts)}")

        # Top values (bounded)
        if top_values:
            value_strs = [str(v) for v, _ in top_values[:10]]
            lines.append(f"  Top values: {', '.join(value_strs)}")

        # Narrative
        if narrative:
            lines.append(f"  {narrative}")

        return lines

    @staticmethod
    def _format_baseline_evidence(evidence: dict[str, Any]) -> list[str]:
        """Format baseline evidence for console display.

        Args:
            evidence: Dictionary representation of BaselineEvidence.

        Returns:
            List of formatted lines for console output.
        """
        lines: list[str] = []
        if not isinstance(evidence, dict):
            return lines

        classification = evidence.get("classification", "unknown")
        reason_code = evidence.get("reason_code", "unknown")
        profile_maturity = evidence.get("profile_maturity", "unknown")
        value_count = evidence.get("value_count", 0)
        rare_threshold = evidence.get("rare_threshold", 0)
        observation_count = evidence.get("observation_count", 0)
        explanation = evidence.get("explanation", "")

        # Header line with classification and reason
        lines.append(f"  Classification: {classification} (reason: {reason_code})")
        lines.append(f"  Profile maturity: {profile_maturity}")

        # Count/threshold context
        if rare_threshold > 0:
            lines.append(f"  Value count: {value_count} (threshold: >{rare_threshold})")
        else:
            lines.append(f"  Value count: {value_count}")
        lines.append(f"  Total observations: {observation_count}")

        # Explanation
        if explanation:
            lines.append(f"  {explanation}")

        return lines

    @staticmethod
    def _format_evidence_items(evidence: Any) -> list[str]:
        """Format structured or mapping evidence for console display.

        Detector evidence is a list of ``{field, observed, condition}``
        entries. Fusion evidence is a list of mappings with category /
        description / weight. Legacy payloads may still be a dict.
        """
        lines: list[str] = []
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                lines.append(f"  {key}: {value}")
            return lines
        if isinstance(evidence, (list, tuple)):
            for item in evidence:
                if not isinstance(item, dict):
                    lines.append(f"  {item}")
                    continue
                field = item.get("field")
                if field is not None:
                    lines.append(f"  {field}: {item.get('observed')}")
                    continue
                category = item.get("category", "evidence")
                description = item.get("description", "")
                weight = item.get("weight")
                suffix = f" (weight {weight})" if weight is not None else ""
                if description:
                    lines.append(f"  {category}: {description}{suffix}")
                else:
                    lines.append(f"  {category}{suffix}")
        return lines

    def is_available(self) -> bool:
        """Check if console is available.

        Returns:
            True (console is always available).
        """
        return self._available

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return self._provider_name

    def __repr__(self) -> str:
        """String representation."""
        return f"ConsoleAlertProvider(colors={self._use_colors})"
