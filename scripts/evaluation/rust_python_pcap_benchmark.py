#!/usr/bin/env python3
"""End-to-end real-PCAP and bounded-state benchmark for PacketHawk and ArgusProwl.

The two products perform different analyses: PacketHawk decodes packets directly,
while ArgusProwl consumes Zeek connection events. Results are therefore reported
as separate pipeline measurements, never as an apples-to-apples detector contest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import resource
import shutil
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctu_idseval import CAPTURES, CTUIDSEvalRunner, EvaluationError

PACKETHAWK_COMMIT = "1166dd76767f533a04a20c749632122f0e119b17"
PACKET_LIMIT = 512 * 1024 * 1024
PACKET_RECORD_LIMIT = 16 * 1024 * 1024


class PreparedRunner(CTUIDSEvalRunner):
    """Reuse a pre-generated Zeek log so Python pipeline time excludes Zeek."""

    prepared_log: Path

    def _run_zeek(self, pcap: Path, output_dir: Path) -> str:
        del pcap, output_dir
        return self.prepared_log.read_text(encoding="utf-8")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)], 3)


def summarize(values: list[float]) -> dict[str, float | None]:
    return {
        "min": round(min(values), 3) if values else None,
        "median": round(statistics.median(values), 3) if values else None,
        "p95": percentile(values, 0.95),
        "max": round(max(values), 3) if values else None,
    }


def run_timed(command: list[str], timeout: int = 900) -> tuple[subprocess.CompletedProcess[str], dict[str, float]]:
    """Run a child process and collect its own CPU and peak-RSS counters."""
    timed = ["/usr/bin/time", "-f", "__PERF__%e,%U,%S,%M", *command]
    started = time.perf_counter()
    completed = subprocess.run(timed, capture_output=True, text=True, timeout=timeout, check=False)
    wall_ms = (time.perf_counter() - started) * 1000
    match = re.search(r"__PERF__(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+(?:\.\d+)?),(\d+)", completed.stderr)
    if match is None:
        raise EvaluationError(f"Missing /usr/bin/time metrics for command: {command[0]}")
    user_s, system_s, max_rss_kib = float(match[2]), float(match[3]), int(match[4])
    return completed, {
        "wall_ms": round(wall_ms, 3),
        "cpu_user_ms": round(user_s * 1000, 3),
        "cpu_system_ms": round(system_s * 1000, 3),
        "cpu_percent_of_one_core": round((user_s + system_s) * 100000 / max(wall_ms, 0.001), 2),
        "peak_rss_mib": round(max_rss_kib / 1024, 3),
    }


def run_python_worker(args: argparse.Namespace) -> None:
    from argusprowl.core.application import Application

    timings = {"app_startup_ms": 0.0, "event_processing_ms": 0.0}
    original_startup = Application.startup
    original_process = Application._process_event

    def timed_startup(app: Application, *pos: Any, **kw: Any) -> Any:
        started = time.perf_counter()
        try:
            return original_startup(app, *pos, **kw)
        finally:
            timings["app_startup_ms"] += (time.perf_counter() - started) * 1000

    def timed_process(app: Application, *pos: Any, **kw: Any) -> Any:
        started = time.perf_counter()
        try:
            return original_process(app, *pos, **kw)
        finally:
            timings["event_processing_ms"] += (time.perf_counter() - started) * 1000

    Application.startup = timed_startup
    Application._process_event = timed_process
    started = time.perf_counter()
    try:
        runner = PreparedRunner(Path(args.worker_workspace), Path(args.worker_workspace) / "unused.json")
        runner.pcap_root = Path(args.pcap_root)
        runner.reference_root = Path(args.reference_root)
        runner.generated_root = Path(args.worker_workspace) / "generated"
        runner.prepared_log = Path(args.conn_log)
        result = runner._evaluate_capture(args.capture)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        elapsed_ms = (time.perf_counter() - started) * 1000
        result.update({
            "worker_wall_ms": round(elapsed_ms, 3),
            "cpu_user_ms": round(usage.ru_utime * 1000, 3),
            "cpu_system_ms": round(usage.ru_stime * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
            **{key: round(value, 3) for key, value in timings.items()},
        })
        print(json.dumps(result, sort_keys=True))
    finally:
        Application.startup = original_startup
        Application._process_event = original_process


def create_python_stress_log(source: Path, destination: Path, event_count: int) -> dict[str, Any]:
    """Amplify real Zeek flow rows with unique IDs/timestamps for a parser/pipeline stress test."""
    fields: list[str] = []
    headers: list[str] = []
    sample: list[str] | None = None
    with source.open(encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("#fields"):
                fields = line.rstrip("\\n").split("\\t")[1:]
                headers.append(line)
            elif line.startswith("#") or not line.strip():
                headers.append(line)
            else:
                sample = line.rstrip("\\r\\n").split("\\t")
                break
    if sample is None or "ts" not in fields or "uid" not in fields:
        raise EvaluationError(f"Cannot derive stress rows from Zeek log: {source}")
    ts_index, uid_index = fields.index("ts"), fields.index("uid")
    if len(sample) != len(fields):
        raise EvaluationError("Zeek sample row does not match #fields")
    base_timestamp = float(sample[ts_index])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as output:
        output.writelines(headers)
        for index in range(event_count):
            row = sample.copy()
            row[ts_index] = f"{base_timestamp + index / 1_000_000:.6f}"
            row[uid_index] = f"AP{index:010d}"
            output.write("\\t".join(row) + "\\n")
    return {
        "classification": "derived_zeek_event_stress_not_real_capture",
        "source_conn_log_sha256": digest(source),
        "events": event_count,
        "file_bytes": destination.stat().st_size,
    }


def run_python_stress_worker(args: argparse.Namespace) -> None:
    from argusprowl.core.application import Application
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.replay.replay_reader import ReplayReader
    from argusprowl.alerting.alert_persistence import AlertPersistence

    workspace = Path(args.worker_workspace)
    state_dir = workspace / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    config_path = state_dir / "evaluation.yaml"
    config_path.write_text("\\n".join([
        "app_name: ArgusProwl Rust/Python stress evaluation",
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
    ]), encoding="utf-8")
    timings = {"app_startup_ms": 0.0, "event_processing_ms": 0.0}
    original_startup = Application.startup
    original_process = Application._process_event

    def timed_startup(app: Application, *pos: Any, **kw: Any) -> Any:
        started = time.perf_counter()
        try:
            return original_startup(app, *pos, **kw)
        finally:
            timings["app_startup_ms"] += (time.perf_counter() - started) * 1000

    def timed_process(app: Application, *pos: Any, **kw: Any) -> Any:
        started = time.perf_counter()
        try:
            return original_process(app, *pos, **kw)
        finally:
            timings["event_processing_ms"] += (time.perf_counter() - started) * 1000

    Application.startup = timed_startup
    Application._process_event = timed_process
    started = time.perf_counter()
    app = Application(config_path=config_path, container=ServiceContainer())
    accepted = rejected = 0
    try:
        app.startup(start_api=False)
        for event in ReplayReader(args.conn_log).read_events():
            if app._process_event(event):
                accepted += 1
            else:
                rejected += 1
        persisted = app._container.resolve(AlertPersistence).list_all()
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result = {
            "classification": "derived_zeek_event_stress_not_detection_efficacy",
            "events_requested": args.stress_events,
            "events_accepted": accepted,
            "events_rejected": rejected,
            "alerts_persisted": len(persisted.alerts) if persisted.status.value == "AVAILABLE" else None,
            "worker_wall_ms": round((time.perf_counter() - started) * 1000, 3),
            "cpu_user_ms": round(usage.ru_utime * 1000, 3),
            "cpu_system_ms": round(usage.ru_stime * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
            **{key: round(value, 3) for key, value in timings.items()},
        }
        print(json.dumps(result, sort_keys=True))
    finally:
        app.shutdown()
        Application.startup = original_startup
        Application._process_event = original_process


def run_python_pipeline(
    script: Path,
    capture: str,
    conn_log: Path,
    pcap_root: Path,
    reference_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    command = [
        sys.executable, str(script), "--python-worker",
        "--capture", capture,
        "--conn-log", str(conn_log),
        "--pcap-root", str(pcap_root),
        "--reference-root", str(reference_root),
        "--worker-workspace", str(workspace),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False)
    if completed.returncode:
        raise EvaluationError(f"ArgusProwl worker failed for {capture}: {completed.stderr[-4000:]}")
    try:
        return json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"Invalid ArgusProwl worker output: {completed.stdout[-2000:]}") from exc


def run_packethawk(binary: Path, pcap: Path, command: str) -> tuple[dict[str, Any], dict[str, float]]:
    if command == "detect":
        args = [str(binary), "capture", "detect", str(pcap), "--json"]
    else:
        args = [str(binary), "capture", "flows", str(pcap), "--json", "--max-active-flows", "100000"]
    completed, metrics = run_timed(args, timeout=1800)
    if completed.returncode:
        raise EvaluationError(f"PacketHawk {command} failed for {pcap.name}: {completed.stderr[-3000:]}")
    try:
        return json.loads(completed.stdout), metrics
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"PacketHawk emitted invalid JSON for {pcap.name}") from exc


def find_template(pcap: Path) -> tuple[bytes, bytes]:
    """Extract one real Ethernet/IPv4 TCP or UDP frame from a classic PCAP."""
    with pcap.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise EvaluationError(f"Truncated PCAP global header: {pcap}")
        magic = header[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            raise EvaluationError("Saturation fixture generation requires classic PCAP input")
        if int.from_bytes(header[20:24], "little" if endian == "<" else "big") != 1:
            raise EvaluationError("Saturation fixture generation currently requires Ethernet link type")
        while packet_header := stream.read(16):
            if len(packet_header) != 16:
                break
            captured = int.from_bytes(packet_header[8:12], "little" if endian == "<" else "big")
            frame = stream.read(captured)
            if len(frame) != captured or len(frame) < 54:
                continue
            if frame[12:14] != b"\x08\x00" or frame[23] not in (6, 17):
                continue
            ihl = (frame[14] & 0x0F) * 4
            if ihl < 20 or len(frame) < 14 + ihl + 4:
                continue
            return header, frame
    raise EvaluationError(f"No supported Ethernet/IPv4 TCP or UDP frame found in {pcap}")


def create_saturation_pcap(source: Path, destination: Path, packet_count: int) -> dict[str, Any]:
    """Create a clearly labelled, real-frame-derived state-capacity stress input."""
    header, template = find_template(source)
    endian = "<" if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    destination.parent.mkdir(parents=True, exist_ok=True)
    frame = bytearray(template)
    ihl = (frame[14] & 0x0F) * 4
    transport = 14 + ihl
    with destination.open("wb") as output:
        output.write(header)
        for index in range(packet_count):
            packet = bytearray(frame)
            source_group = index // 4096 + 1
            source_ip = (0x0A000000 | source_group).to_bytes(4, "big")
            packet[26:30] = source_ip
            packet[30:34] = bytes((198, 51, 100, 1))
            packet[transport:transport + 2] = (40000).to_bytes(2, "big")
            packet[transport + 2:transport + 4] = (index % 4096 + 1).to_bytes(2, "big")
            ip_header = packet[14:14 + ihl]
            ip_header[10:12] = b"\x00\x00"
            checksum = 0
            for offset in range(0, len(ip_header), 2):
                checksum += (ip_header[offset] << 8) | ip_header[offset + 1]
            while checksum >> 16:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)
            ip_header[10:12] = (~checksum & 0xFFFF).to_bytes(2, "big")
            packet[14:14 + ihl] = ip_header
            fraction = index
            record = (
                (1_700_000_000).to_bytes(4, "little" if endian == "<" else "big")
                + fraction.to_bytes(4, "little" if endian == "<" else "big")
                + len(packet).to_bytes(4, "little" if endian == "<" else "big")
                + len(packet).to_bytes(4, "little" if endian == "<" else "big")
            )
            output.write(record)
            output.write(packet)
    return {
        "classification": "derived_saturation_fixture_not_real_capture",
        "source_pcap_sha256": digest(source),
        "packets": packet_count,
        "file_bytes": destination.stat().st_size,
        "unique_source_groups": math.ceil(packet_count / 4096),
        "source_frame_protocol": "TCP" if template[23] == 6 else "UDP",
    }


def boundary_checks(binary: Path, workspace: Path) -> dict[str, Any]:
    """Exercise fail-fast parser limits with sparse files; no large allocation required."""
    workspace.mkdir(parents=True, exist_ok=True)
    over_capture = workspace / "over-capture-limit.pcap"
    with over_capture.open("wb") as stream:
        stream.truncate(PACKET_LIMIT + 1)
    oversized_packet = workspace / "over-packet-limit.pcap"
    endian = "little"
    with oversized_packet.open("wb") as stream:
        stream.write(bytes.fromhex("d4c3b2a10200040000000000000000000100000001000000"))
        stream.write((1).to_bytes(4, endian) + (0).to_bytes(4, endian))
        stream.write((PACKET_RECORD_LIMIT + 1).to_bytes(4, endian))
        stream.write((PACKET_RECORD_LIMIT + 1).to_bytes(4, endian))
    oversized_block = workspace / "over-pcapng-block.pcapng"
    with oversized_block.open("wb") as stream:
        stream.write(
            b"\\x0a\\x0d\\x0d\\x0a"
            + (28).to_bytes(4, "little")
            + b"\\x4d\\x3c\\x2b\\x1a"
            + (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + (28).to_bytes(4, "little")
        )
        stream.write((6).to_bytes(4, "little"))
        stream.write((16 * 1024 * 1024 + 4100).to_bytes(4, "little"))
    checks = {}
    for name, path, expected in (
        ("capture_size", over_capture, "configured safety limit"),
        ("packet_record_size", oversized_packet, "packet record exceeds"),
        ("pcapng_block_size", oversized_block, "PCAPNG block exceeds"),
    ):
        completed = subprocess.run(
            [str(binary), "capture", "detect", str(path), "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        checks[name] = {
            "rejected": completed.returncode != 0,
            "expected_error": expected in completed.stderr,
            "stderr": completed.stderr[-500:],
        }
        if not checks[name]["rejected"] or not checks[name]["expected_error"]:
            raise EvaluationError(f"PacketHawk boundary check failed: {name}")
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--packethawk-bin", type=Path)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--stress-packets", type=int, default=262144)
    parser.add_argument("--python-worker", action="store_true")
    parser.add_argument("--python-stress-worker", action="store_true")
    parser.add_argument("--stress-events", type=int, default=0)
    parser.add_argument("--capture")
    parser.add_argument("--conn-log", type=Path)
    parser.add_argument("--pcap-root", type=Path)
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--worker-workspace", type=Path)
    args = parser.parse_args()

    if args.python_worker:
        run_python_worker(args)
        return
    if args.python_stress_worker:
        run_python_stress_worker(args)
        return
    if args.repeats < 1 or args.stress_packets < 250000:
        raise SystemExit("--repeats must be >= 1 and --stress-packets must be >= 250000")
    if args.workspace is None or args.output is None or args.packethawk_bin is None:
        raise SystemExit("--workspace, --output, and --packethawk-bin are required")

    workspace = args.workspace.resolve()
    output = args.output.resolve()
    binary = args.packethawk_bin.resolve()
    runner = CTUIDSEvalRunner(workspace / "dataset-work", workspace / "dataset-work" / "unused.json")
    archive_checksums = runner._download()
    runner._prepare_dataset(archive_checksums)
    zeek_version = subprocess.run(
        ["docker", "run", "--rm", runner.zeek_image, "zeek", "--version"],
        capture_output=True, text=True, check=True, timeout=120,
    ).stdout.strip()

    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "argusprowl_commit": os.environ.get("GITHUB_SHA"),
        "packethawk_commit": PACKETHAWK_COMMIT,
        "python_version": platform.python_version(),
        "rustc_version": subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "zeek_version": zeek_version,
        "runner": {
            "os": platform.platform(),
            "cpu_count": os.cpu_count(),
            "repeats": args.repeats,
            "stress_packets": args.stress_packets,
        },
        "dataset": {
            "name": "CTU-IDSEVAL-6",
            "doi": "10.5281/zenodo.21027042",
            "license": "CC-BY-4.0",
            "archive_md5": archive_checksums,
        },
        "comparison_boundary": (
            "Not an apples-to-apples detector comparison: PacketHawk processes raw packets; "
            "ArgusProwl processes Zeek-normalized connection events. Zeek conversion is timed "
            "separately and included in the ArgusProwl end-to-end total. Detection semantics "
            "and output counts are reported independently."
        ),
        "startup_probes": {},
        "captures": [],
    }

    rust_boot = []
    python_boot = []
    for _ in range(5):
        start = time.perf_counter()
        subprocess.run([str(binary), "--version"], capture_output=True, check=True, timeout=30)
        rust_boot.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, "-c", "import argusprowl, argusprowl.core.application"],
            capture_output=True, check=True, timeout=60,
        )
        python_boot.append((time.perf_counter() - start) * 1000)
    report["startup_probes"] = {
        "packethawk_process_start_ms": summarize(rust_boot),
        "argusprowl_import_start_ms": summarize(python_boot),
        "samples": 5,
        "note": "Process/import startup probes, not full application cold-start timings.",
    }

    for capture in CAPTURES:
        pcap = next(runner.pcap_root.rglob(f"{capture}.pcap"))
        generated_dir = workspace / "generated-zeek" / capture
        started = time.perf_counter()
        runner._run_zeek(pcap, generated_dir)
        zeek_ms = (time.perf_counter() - started) * 1000
        conn_log = generated_dir / "conn.log"
        capture_result: dict[str, Any] = {
            "capture_id": capture,
            "pcap_sha256": digest(pcap),
            "pcap_bytes": pcap.stat().st_size,
            "zeek_conn_log_bytes": conn_log.stat().st_size,
            "zeek_conversion_ms": round(zeek_ms, 3),
            "packethawk": [],
            "argusprowl": [],
        }
        for repeat in range(args.repeats):
            rust_detect, rust_detect_metrics = run_packethawk(binary, pcap, "detect")
            rust_flows, rust_flow_metrics = run_packethawk(binary, pcap, "flows")
            capture_result["packethawk"].append({
                "repeat": repeat + 1,
                "detect_metrics": rust_detect_metrics,
                "flow_metrics": rust_flow_metrics,
                "detection_stats": rust_detect.get("stats", {}),
                "flow_stats": rust_flows.get("stats", {}),
                "vertical_scan_alerts": rust_detect.get("port_scan", {}).get("stats", {}).get("vertical_alerts"),
                "horizontal_scan_alerts": rust_detect.get("port_scan", {}).get("stats", {}).get("horizontal_alerts"),
                "beacon_alerts": rust_detect.get("beaconing", {}).get("stats", {}).get("alerts"),
                "dns_anomaly_alerts": rust_detect.get("dns_anomaly", {}).get("stats", {}).get("anomalous_queries"),
            })
            python_workspace = workspace / "python-workers" / capture / f"run-{repeat + 1}"
            python_result = run_python_pipeline(
                Path(__file__).resolve(), capture, conn_log,
                runner.pcap_root, runner.reference_root, python_workspace,
            )
            capture_result["argusprowl"].append({
                "repeat": repeat + 1,
                **python_result,
                "zeek_conversion_ms": round(zeek_ms, 3),
                "end_to_end_ms_including_zeek": round(zeek_ms + python_result["worker_wall_ms"], 3),
            })
        report["captures"].append(capture_result)

    first_pcap = next(runner.pcap_root.rglob(f"{CAPTURES[0]}.pcap"))
    stress_path = workspace / "stress" / "derived-state-saturation.pcap"
    stress_fixture = create_saturation_pcap(first_pcap, stress_path, args.stress_packets)
    stress_detect, stress_detect_metrics = run_packethawk(binary, stress_path, "detect")
    stress_flows, stress_flow_metrics = run_packethawk(binary, stress_path, "flows")
    report["stress"] = {
        **stress_fixture,
        "packethawk_detect_metrics": stress_detect_metrics,
        "packethawk_flow_metrics": stress_flow_metrics,
        "detection_stats": stress_detect.get("stats", {}),
        "flow_stats": stress_flows.get("stats", {}),
        "state_evictions": stress_detect.get("stats", {}).get("state_evictions"),
        "flow_evictions": stress_flows.get("stats", {}).get("flows_evicted"),
        "expected_saturation_observed": (
            stress_detect.get("stats", {}).get("state_evictions", 0) > 0
            and stress_flows.get("stats", {}).get("flows_evicted", 0) > 0
        ),
    }
    python_stress_log = workspace / "stress" / "derived-zeek-events.log"
    python_stress_fixture = create_python_stress_log(
        next((workspace / "generated-zeek" / CAPTURES[0]).glob("conn.log")),
        python_stress_log,
        args.stress_packets,
    )
    python_stress_workspace = workspace / "python-stress-worker"
    python_stress_command = [
        sys.executable, str(Path(__file__).resolve()), "--python-stress-worker",
        "--conn-log", str(python_stress_log),
        "--worker-workspace", str(python_stress_workspace),
        "--stress-events", str(args.stress_packets),
    ]
    python_stress = subprocess.run(
        python_stress_command, capture_output=True, text=True, timeout=3600, check=False
    )
    if python_stress.returncode:
        raise EvaluationError(f"ArgusProwl stress worker failed: {python_stress.stderr[-4000:]}")
    try:
        python_stress_result = json.loads(python_stress.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise EvaluationError("ArgusProwl stress worker emitted invalid JSON") from exc
    report["stress"]["argusprowl_fixture"] = python_stress_fixture
    report["stress"]["argusprowl"] = python_stress_result
    report["packethawk_boundary_checks"] = boundary_checks(binary, workspace / "boundary")
    if not report["stress"]["expected_saturation_observed"]:
        raise EvaluationError("Derived saturation workload did not exercise bounded state eviction")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "captures": len(report["captures"]),
        "stress_packets": args.stress_packets,
        "stress_state_evictions": report["stress"]["state_evictions"],
        "stress_flow_evictions": report["stress"]["flow_evictions"],
    }, indent=2))


if __name__ == "__main__":
    main()
