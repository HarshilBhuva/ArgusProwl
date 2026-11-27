#!/usr/bin/env python3
"""Replay CTU-IDSEVAL-6 raw PCAPs through Zeek and ArgusProwl."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import urllib.request
import zipfile
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DATASET_DOI = "10.5281/zenodo.21027042"
ARCHIVES = {
    "pcap.zip": ("https://zenodo.org/records/21027042/files/pcap.zip?download=1", "bb4476af2b9d4b8ce875dda88a0cca7b"),
    "zeek.zip": ("https://zenodo.org/records/21027042/files/zeek.zip?download=1", "33b57c813053eed12ec3738b65f27ef0"),
}
CAPTURES = (
    "ctu-idseval-6-benign-user-traffic-1",
    "ctu-idseval-6-malicious-malware-1",
    "ctu-idseval-6-malicious-malware-2",
    "ctu-idseval-6-malicious-portscan-1",
    "ctu-idseval-6-malicious-portscan-2",
    "ctu-idseval-6-malicious-portscan-3",
)
FLOW_KEY_FIELDS = ("ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")


class EvaluationError(RuntimeError):
    """Raised when benchmark inputs or results cannot be trusted."""


def flow_key(record: dict[str, str]) -> tuple[str, ...]:
    return tuple(record.get(field, "-") for field in FLOW_KEY_FIELDS)


def calculate_metrics(labels_and_predictions: list[tuple[str, bool]]) -> dict[str, Any]:
    """Calculate flow-level binary metrics; Background is excluded."""
    tp = fp = fn = tn = background = 0
    for label, predicted in labels_and_predictions:
        normalized = label.strip().casefold()
        if normalized == "background":
            background += 1
        elif normalized == "malicious":
            if predicted:
                tp += 1
            else:
                fn += 1
        elif normalized == "benign":
            if predicted:
                fp += 1
            else:
                tn += 1
        else:
            raise EvaluationError(f"Unsupported ground-truth label: {label!r}")

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 6) if denominator else None

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if precision is not None and recall is not None and precision + recall
        else (0.0 if precision == 0.0 or recall == 0.0 else None)
    )
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "background_excluded": background,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": ratio(fp, fp + tn),
    }


class CTUIDSEvalRunner:
    """Download, validate, replay, and evaluate the six public CTU captures."""

    def __init__(
        self,
        workspace: Path,
        output: Path,
        *,
        zeek_image: str = "zeek/zeek:9.0.1",
        minimum_label_match: float = 0.999,
    ) -> None:
        if not 0.95 <= minimum_label_match <= 1.0:
            raise ValueError("minimum_label_match must be between 0.95 and 1.0")
        self.workspace = workspace.resolve()
        self.output = output.resolve()
        self.zeek_image = zeek_image
        self.minimum_label_match = minimum_label_match
        self.dataset_root = self.workspace / "dataset"
        self.pcap_root = self.dataset_root / "pcap"
        self.reference_root = self.dataset_root / "zeek"
        self.generated_root = self.workspace / "generated-zeek"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.generated_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(path: Path, algorithm: str) -> str:
        digest = hashlib.new(algorithm, usedforsecurity=False) if algorithm == "md5" else hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _download(self) -> dict[str, str]:
        checksums: dict[str, str] = {}
        for filename, (url, expected_md5) in ARCHIVES.items():
            destination = self.workspace / filename
            if not destination.is_file() or self._digest(destination, "md5") != expected_md5:
                temporary = destination.with_suffix(destination.suffix + ".partial")
                temporary.unlink(missing_ok=True)
                request = urllib.request.Request(url, headers={"User-Agent": "ArgusProwl-CTU-IDSEVAL/1.0"})
                try:
                    with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
                        shutil.copyfileobj(response, output)
                except Exception:
                    temporary.unlink(missing_ok=True)
                    raise
                if self._digest(temporary, "md5") != expected_md5:
                    temporary.unlink(missing_ok=True)
                    raise EvaluationError(f"Zenodo-published MD5 mismatch: {filename}")
                temporary.replace(destination)
            checksums[filename] = self._digest(destination, "md5")
        return checksums

    @staticmethod
    def _safe_extract(archive: Path, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        root = destination.resolve()
        with zipfile.ZipFile(archive) as zipped:
            corrupt = zipped.testzip()
            if corrupt:
                raise EvaluationError(f"Corrupt ZIP member: {corrupt}")
            for member in zipped.infolist():
                target = (destination / member.filename).resolve()
                if target != root and root not in target.parents:
                    raise EvaluationError(f"Unsafe archive member path: {member.filename}")
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)

    def _prepare_dataset(self, checksums: dict[str, str]) -> None:
        if not (self.pcap_root.is_dir() and self.reference_root.is_dir()):
            extracted = self.dataset_root / "extracted"
            self._safe_extract(self.workspace / "pcap.zip", extracted)
            self._safe_extract(self.workspace / "zeek.zip", extracted)
            pcap_dir = next(extracted.rglob("pcap"), None)
            zeek_dir = next(extracted.rglob("zeek"), None)
            if pcap_dir is None or zeek_dir is None:
                raise EvaluationError("Dataset archives must contain pcap/ and zeek/ directories.")
            if not self.pcap_root.exists():
                shutil.copytree(pcap_dir, self.pcap_root)
            if not self.reference_root.exists():
                shutil.copytree(zeek_dir, self.reference_root)
        for capture in CAPTURES:
            if not list(self.pcap_root.rglob(f"{capture}.pcap")):
                raise EvaluationError(f"Missing raw PCAP: {capture}")
            if not list(self.reference_root.rglob(f"{capture}.conn-labeled.log")):
                raise EvaluationError(f"Missing labeled reference: {capture}")
        (self.workspace / "archive-checksums.json").write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _run_zeek(self, pcap: Path, output_dir: Path) -> str:
        output_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none",
                "--volume", f"{pcap.resolve()}:/input.pcap:ro",
                "--volume", f"{output_dir.resolve()}:/out",
                "--workdir", "/out", self.zeek_image, "zeek", "-r", "/input.pcap",
            ],
            check=True, timeout=900, capture_output=True, text=True,
        )
        conn_log = output_dir / "conn.log"
        if not conn_log.is_file() or not conn_log.stat().st_size:
            raise EvaluationError(f"Zeek generated no conn.log for {pcap.name}")
        return conn_log.read_text(encoding="utf-8")

    @staticmethod
    def _read_label_index(path: Path):
        fields: list[str] = []
        by_uid: dict[str, tuple[str, str]] = {}
        by_key: dict[tuple[str, ...], deque[tuple[str, str]]] = defaultdict(deque)
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    continue
                if not line.strip() or line.startswith("#"):
                    continue
                if not fields:
                    raise EvaluationError(f"Missing #fields header in {path}")
                values = line.rstrip("\r\n").split("\t")
                if len(values) != len(fields):
                    raise EvaluationError(f"Column count mismatch in {path}")
                record = dict(zip(fields, values, strict=True))
                label = record.get("label")
                if label not in {"Benign", "Malicious", "Background"}:
                    raise EvaluationError(f"Unsupported ground-truth label: {label!r}")
                pair = (label, record.get("detailedlabel", ""))
                uid = record.get("uid", "-")
                if uid and uid != "-":
                    if uid in by_uid:
                        raise EvaluationError(f"Duplicate reference UID: {uid}")
                    by_uid[uid] = pair
                by_key[flow_key(record)].append(pair)
        if not by_uid and not by_key:
            raise EvaluationError(f"No labeled flows in {path}")
        return by_uid, by_key

    @staticmethod
    def _iter_generated_events(text: str):
        from argusprowl.collectors.zeek.parser import ZeekConnLogParser
        from argusprowl.exceptions.exceptions import ParserError

        parser = ZeekConnLogParser()
        for line in text.splitlines():
            if line.startswith("#fields"):
                parser.set_fields(line.split("\t")[1:])
                continue
            if not line.strip() or line.startswith("#"):
                continue
            try:
                event = parser.parse(line)
            except ParserError as exc:
                raise EvaluationError(f"Generated conn.log parse error: {exc}") from exc
            yield line, event

    def _evaluate_capture(self, capture_id: str) -> dict[str, Any]:
        from argusprowl.alerting.alert_persistence import AlertPersistence
        from argusprowl.core.application import Application
        from argusprowl.dependency_injection.container import ServiceContainer

        pcap = next(self.pcap_root.rglob(f"{capture_id}.pcap"))
        reference = next(self.reference_root.rglob(f"{capture_id}.conn-labeled.log"))
        generated = self._run_zeek(pcap, self.generated_root / capture_id)
        uid_labels, key_labels = self._read_label_index(reference)
        state_dir = self.workspace / "state" / capture_id
        state_dir.mkdir(parents=True, exist_ok=True)
        config_path = state_dir / "evaluation.yaml"
        config_path.write_text(
            "\n".join([
                "app_name: ArgusProwl CTU-IDSEVAL-6 evaluation",
                "logging:",
                "  console_enabled: false",
                "  file_enabled: false",
                "  json_enabled: false",
                "api:",
                "  enabled: false",
                "storage:",
                f"  database_path: {(state_dir / 'evidence.db').as_posix()}",
                "telemetry_evidence:",
                "  enabled: false",
                "alert_persistence:",
                "  enabled: true",
                "  max_alerts: 400000",
                f"  db_path: {(state_dir / 'alerts.db').as_posix()}",
                "attck:",
                "  enabled: false",
                "temporal:",
                "  enabled: false",
                "baseline:",
                "  enabled: false",
                "",
            ]),
            encoding="utf-8",
        )
        app = Application(config_path=config_path, container=ServiceContainer())
        event_labels: dict[Any, tuple[str, str]] = {}
        unmatched = processed = 0
        persisted = None
        try:
            app.startup(start_api=False)
            for line, event in self._iter_generated_events(generated):
                values = line.split("\t")
                record = dict(zip(FLOW_KEY_FIELDS, (values[0], values[2], values[3], values[4], values[5], values[6]), strict=True))
                pair = uid_labels.get(event.source_record_id) if event.source_record_id else None
                if pair is None:
                    candidates = key_labels.get(flow_key(record))
                    if candidates:
                        pair = candidates.popleft()
                if pair is None:
                    unmatched += 1
                else:
                    event_labels[event.event_id] = pair
                if not app._process_event(event):
                    raise EvaluationError(f"ArgusProwl rejected Zeek flow {event.source_record_id}")
                processed += 1
            persisted = app._container.resolve(AlertPersistence).list_all()
        finally:
            app.shutdown()

        if persisted is None or persisted.status.value != "AVAILABLE":
            raise EvaluationError(f"Alert persistence unavailable for {capture_id}")
        alerted = {
            alert.detection_source_event_id
            for alert in persisted.alerts
            if alert.detection_source_event_id is not None
        }
        predictions = [(label[0], event_id in alerted) for event_id, label in event_labels.items()]
        metrics = calculate_metrics(predictions)
        match_rate = len(event_labels) / processed if processed else 0.0
        if match_rate < self.minimum_label_match:
            raise EvaluationError(
                f"Label alignment {match_rate:.4%} for {capture_id} is below "
                f"{self.minimum_label_match:.2%}"
            )
        return {
            "capture_id": capture_id,
            "pcap_sha256": self._digest(pcap, "sha256"),
            "generated_flows": processed,
            "ground_truth_matched": len(event_labels),
            "ground_truth_unmatched": unmatched,
            "ground_truth_match_rate": round(match_rate, 6),
            "label_counts": dict(Counter(label[0] for label in event_labels.values())),
            "alerts": len(persisted.alerts),
            "alerts_without_source_event": sum(
                alert.detection_source_event_id is None for alert in persisted.alerts
            ),
            "metrics": metrics,
        }

    def run(self) -> dict[str, Any]:
        from argusprowl import __version__ as app_version

        checksums = self._download()
        self._prepare_dataset(checksums)
        zeek_version = subprocess.run(
            ["docker", "run", "--rm", self.zeek_image, "zeek", "--version"],
            check=True, timeout=120, capture_output=True, text=True,
        ).stdout.strip()
        captures = [self._evaluate_capture(capture) for capture in CAPTURES]
        totals = {
            key: sum(capture["metrics"][key] for capture in captures)
            for key in ("true_positive", "false_positive", "false_negative", "true_negative", "background_excluded")
        }
        tp, fp, fn, tn = (totals[key] for key in ("true_positive", "false_positive", "false_negative", "true_negative"))
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        totals.update({
            "precision": round(precision, 6) if precision is not None else None,
            "recall": round(recall, 6) if recall is not None else None,
            "f1": (
                round(2 * precision * recall / (precision + recall), 6)
                if precision is not None and recall is not None and precision + recall
                else (0.0 if precision == 0.0 or recall == 0.0 else None)
            ),
            "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else None,
        })
        rule_hashes = {
            rule_path.name: self._digest(rule_path, "sha256")
            for rule_path in sorted(Path("config/rules").glob("*.yaml"))
        }
        report = {
            "rule_sha256": rule_hashes,
            "dataset": {
                "name": "CTU-IDSEVAL-6",
                "doi": DATASET_DOI,
                "url": "https://zenodo.org/records/21027042",
                "license": "CC-BY-4.0",
                "archive_md5": checksums,
            },
            "generated_at": datetime.now(UTC).isoformat(),
            "application_version": app_version,
            "git_commit": os.environ.get("GITHUB_SHA"),
            "python_version": platform.python_version(),
            "zeek_image": self.zeek_image,
            "zeek_version": zeek_version,
            "minimum_label_match": self.minimum_label_match,
            "metric_semantics": (
                "Flow-level. Positive only when an alert names the exact flow as "
                "detection_source_event_id. Background labels are excluded from binary metrics."
            ),
            "captures": captures,
            "overall": totals,
        }
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(self.output), "overall": totals}, indent=2))
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zeek-image", default="zeek/zeek:9.0.1")
    parser.add_argument("--minimum-label-match", type=float, default=0.999)
    args = parser.parse_args()
    CTUIDSEvalRunner(
        args.workspace, args.output, zeek_image=args.zeek_image,
        minimum_label_match=args.minimum_label_match,
    ).run()


if __name__ == "__main__":
    main()
