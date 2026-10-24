"""Unit tests for TLSFlowFeatureExtractor.

The extractor takes a duck-typed query client, so tests inject a fake
client and avoid live ClickHouse dependencies at collection or run time.
"""

import pytest

from argusprowl.feature_engineering.tls_flow_extractor import TLSFlowFeatureExtractor


class FakeQueryClient:
    """Minimal in-memory stand-in for a ClickHouse query client."""

    def __init__(self, rows: list[dict] | None = None, queries: list[str] | None = None):
        self._rows = rows or []
        self.queries = queries if queries is not None else []

    def query(self, sql: str) -> list[dict]:
        self.queries.append(sql)
        return list(self._rows)


@pytest.fixture
def extractor() -> TLSFlowFeatureExtractor:
    return TLSFlowFeatureExtractor()


def test_empty_result_returns_expected_columns(extractor: TLSFlowFeatureExtractor) -> None:
    client = FakeQueryClient(rows=[])

    result = extractor.extract_features_from_clickhouse(client, time_window_minutes=5)

    assert list(result.columns) == [
        "id_orig_h",
        "id_resp_h",
        "connection_count",
        "avg_duration",
        "stddev_duration",
        "avg_orig_bytes",
        "avg_resp_bytes",
        "byte_ratio",
        "delta_t_mean",
        "delta_t_std",
        "delta_t_cv",
        "has_sni",
        "is_tls13",
        "sni_entropy",
        "ja3_homogeneity",
    ]
    assert result.empty
    assert client.queries
    assert "INTERVAL 5 MINUTE" in client.queries[0]


def test_time_window_validation(extractor: TLSFlowFeatureExtractor) -> None:
    client = FakeQueryClient(rows=[])

    with pytest.raises(ValueError, match="time_window_minutes must be positive"):
        extractor.extract_features_from_clickhouse(client, time_window_minutes=0)
    with pytest.raises(ValueError, match="time_window_minutes must be positive"):
        extractor.extract_features_from_clickhouse(client, time_window_minutes=-1)
    assert client.queries == []


def test_single_connection_features(extractor: TLSFlowFeatureExtractor) -> None:
    client = FakeQueryClient(
        rows=[
            {
                "id_orig_h": "1.1.1.1",
                "id_resp_h": "2.2.2.2",
                "ts": 1_700_000_000.0,
                "duration": 0.5,
                "orig_bytes": 100,
                "resp_bytes": 200,
                "server_name": "example.com",
                "version": "1.3",
            }
        ]
    )

    result = extractor.extract_features_from_clickhouse(client, time_window_minutes=5)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["connection_count"] == 1
    assert row["avg_duration"] == 0.5
    assert row["stddev_duration"] == 0.0
    assert row["byte_ratio"] == 0.5
    assert row["delta_t_mean"] == 0.0
    assert row["delta_t_cv"] == 0.0
    assert row["has_sni"] == 1
    assert row["is_tls13"] == 1
    assert row["ja3_homogeneity"] == 1.0


def test_multiple_connections_delta_stats_and_grouping(extractor: TLSFlowFeatureExtractor) -> None:
    client = FakeQueryClient(
        rows=[
            {
                "id_orig_h": "1.1.1.1",
                "id_resp_h": "2.2.2.2",
                "ts": 1_700_000_000.0,
                "duration": 1.0,
                "orig_bytes": 10,
                "resp_bytes": 20,
                "server_name": "a.example",
                "version": "1.2",
            },
            {
                "id_orig_h": "1.1.1.1",
                "id_resp_h": "2.2.2.2",
                "ts": 1_700_000_005.0,
                "duration": 3.0,
                "orig_bytes": 50,
                "resp_bytes": 100,
                "server_name": "b.example",
                "version": "1.3",
            },
            {
                "id_orig_h": "3.3.3.3",
                "id_resp_h": "4.4.4.4",
                "ts": 1_700_000_001.0,
                "duration": 2.0,
                "orig_bytes": 1,
                "resp_bytes": 2,
                "server_name": "",
                "version": "TLSv13",
            },
        ]
    )

    result = extractor.extract_features_from_clickhouse(client, time_window_minutes=5)
    pair = result[(result["id_orig_h"] == "1.1.1.1") & (result["id_resp_h"] == "2.2.2.2")].iloc[0]
    other = result[(result["id_orig_h"] == "3.3.3.3") & (result["id_resp_h"] == "4.4.4.4")].iloc[0]

    assert len(result) == 2
    assert pair["connection_count"] == 2
    assert pair["delta_t_mean"] == 5.0
    assert pair["delta_t_std"] == 0.0
    assert pair["delta_t_cv"] == 0.0
    assert pair["has_sni"] == 1
    assert pair["is_tls13"] == 1
    assert other["connection_count"] == 1
    assert other["has_sni"] == 0
    assert other["is_tls13"] == 1
    assert other["byte_ratio"] == 0.5
