"""Tests for CTU-IDSEVAL-6 evaluation metrics and archive safety."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from scripts.evaluation.ctu_idseval import (
    CTUIDSEvalRunner,
    EvaluationError,
    build_evaluation_config,
    calculate_metrics,
)


def test_binary_metrics_exclude_background():
    result = calculate_metrics([
        ("Malicious", True), ("Malicious", False),
        ("Benign", True), ("Benign", False),
        ("Background", True),
    ])
    assert result == {
        "true_positive": 1, "false_positive": 1,
        "false_negative": 1, "true_negative": 1,
        "background_excluded": 1, "precision": 0.5,
        "recall": 0.5, "f1": 0.5, "false_positive_rate": 0.5,
    }


def test_metrics_report_undefined_denominators_as_none():
    result = calculate_metrics([("Background", False)])
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["false_positive_rate"] is None


def test_metrics_reject_unknown_ground_truth_label():
    with pytest.raises(EvaluationError, match="Unsupported ground-truth label"):
        calculate_metrics([("Unknown", False)])


def test_runner_rejects_unrealistic_label_match_threshold(tmp_path: Path):
    with pytest.raises(ValueError, match="minimum_label_match"):
        CTUIDSEvalRunner(tmp_path / "work", tmp_path / "report.json", minimum_label_match=0.8)


def test_archive_extraction_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escape.txt", "no")
    with pytest.raises(EvaluationError, match="Unsafe archive member"):
        CTUIDSEvalRunner._safe_extract(archive, tmp_path / "extract")


def test_label_index_counts_reference_flows_and_builds_uid_and_tuple_indexes(tmp_path: Path):
    reference = tmp_path / "capture.conn-labeled.log"
    reference.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
        "\tproto\tlabel\tdetailedlabel\n"
        "1.0\tC1\t192.0.2.10\t12345\t198.51.100.20\t443"
        "\ttcp\tMalicious\tCC\n",
        encoding="utf-8",
    )

    uid_labels, key_labels, reference_count = CTUIDSEvalRunner._read_label_index(
        reference
    )

    assert reference_count == 1
    assert uid_labels["C1"] == ("Malicious", "CC")
    flow = ("1.0", "192.0.2.10", "12345", "198.51.100.20", "443", "tcp")
    assert len(key_labels[flow]) == 1


def test_per_rule_metrics_are_independent_and_exclude_background():
    from scripts.evaluation.ctu_idseval import calculate_rule_metrics

    labels = {
        "malicious-1": ("Malicious", "scan"),
        "benign-1": ("Benign", "normal"),
        "background-1": ("Background", "background"),
    }
    result = calculate_rule_metrics(
        labels,
        {
            "port_scan": {"malicious-1"},
            "noisy_rule": {"benign-1", "background-1"},
        },
    )

    assert result["port_scan"]["true_positive"] == 1
    assert result["port_scan"]["false_positive"] == 0
    assert result["port_scan"]["false_negative"] == 0
    assert result["noisy_rule"]["false_positive"] == 1
    assert result["noisy_rule"]["background_excluded"] == 1
    assert result["noisy_rule"]["referenced_labeled_events"] == 1


def test_evaluation_config_keeps_temporal_beaconing_enabled(tmp_path: Path):
    import yaml

    config = yaml.safe_load(build_evaluation_config(tmp_path))

    assert config["temporal"]["enabled"] is True
    assert config["temporal"]["min_observations"] == 10
    assert config["temporal"]["min_duration_seconds"] == 300.0
    assert config["temporal"]["periodicity_threshold"] == 0.7
