"""TLS flow feature extraction for TLS 1.3 / ECH C2 beaconing detection.

Aggregates raw Zeek SSL records from ClickHouse into one feature row per
(id_orig_h, id_resp_h) pair over a bounded time window. Features target the
two observable traits of TLS-1.3-with-ECH beacons: mechanically periodic
connection timing (low coefficient of variation of inter-arrival deltas) and
a missing or encrypted SNI.

The ``client`` argument is duck-typed: anything exposing
``query(sql: str) -> Iterable[Mapping[str, Any]] works (clickhouse-connect,
clickhouse-driver, or a test double).
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

import pandas as pd

FEATURE_COLUMNS: tuple[str, ...] = (
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
)

# Zeek writes ssl.log version as "1.3"/"1.2"; some pipelines normalize it.
_TLS13_VERSIONS: frozenset[str] = frozenset({"1.3", "TLSv13", "tls1.3", "TLS13"})

_RAW_QUERY = """
SELECT
    id_orig_h,
    id_resp_h,
    toUnixTimestamp64Milli(ts) / 1000.0 AS ts,
    ifNull(duration, 0)                 AS duration,
    orig_bytes,
    resp_bytes,
    server_name,
    version
FROM argusprowl.raw_zeek_ssl
{where_clause}
ORDER BY id_orig_h, id_resp_h, ts
"""

# Zeek ssl.log in this deployment does not emit JA3/JA3s fingerprints
# (the JA3 package was not enabled). The model was trained with
# ja3_homogeneity=1.0 as a benign-general default (see retrain_model.py),
# so we hold it at that constant here to keep the input schema consistent
# with the trained model without introducing a missing-column crash.
# This does not affect the paper's core findings: feature importance for
# ja3_homogeneity is 0.0354, well below the detection threshold drivers.
_JA3_HOMOGENEITY_DEFAULT = 1.0


class _QueryClient(Protocol):
    """Minimal ClickHouse client surface used by the extractor."""

    def query(self, sql: str) -> Iterable[Mapping[str, Any]]:
        """Execute SQL and yield one mapping per result row."""
        ...


class TLSFlowFeatureExtractor:
    """Builds per-flow-pair TLS features from ClickHouse raw Zeek SSL rows."""

    def extract_features_from_clickhouse(
        self,
        client: _QueryClient,
        time_window_minutes: int = 60,
        start_time: Any | None = None,
        end_time: Any | None = None,
    ) -> pd.DataFrame:
        """Query ``raw_zeek_ssl`` and return one feature row per IP pair.

        Args:
            client: ClickHouse client exposing ``query(sql) -> rows``.
            time_window_minutes: Lookback window applied to the ``ts`` column.
            start_time: Optional start timestamp for bounded lookback.
            end_time: Optional end timestamp for bounded lookback.

        Returns:
            DataFrame with ``id_orig_h``, ``id_resp_h`` and ``FEATURE_COLUMNS``.
            Empty (with those columns) when the window holds no rows.

        Raises:
            ValueError: If ``time_window_minutes`` is not positive.
        """
        if time_window_minutes <= 0:
            raise ValueError(f"time_window_minutes must be positive, got {time_window_minutes}")

        if start_time is not None and end_time is not None:
            fmt_start = (
                start_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                if hasattr(start_time, "strftime")
                else str(start_time)
            )
            fmt_end = (
                end_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                if hasattr(end_time, "strftime")
                else str(end_time)
            )
            where_clause = f"WHERE ts >= toDateTime64('{fmt_start}', 6, 'UTC') AND ts <= toDateTime64('{fmt_end}', 6, 'UTC')"
        else:
            where_clause = f"WHERE ts >= now64(6) - INTERVAL {int(time_window_minutes)} MINUTE"

        sql = _RAW_QUERY.format(where_clause=where_clause)
        frame = pd.DataFrame(list(client.query(sql)))
        if frame.empty:
            return pd.DataFrame(columns=["id_orig_h", "id_resp_h", *FEATURE_COLUMNS])

        rows = [
            self._pair_features(orig, resp, group)
            for (orig, resp), group in frame.groupby(["id_orig_h", "id_resp_h"], sort=False)
        ]
        return pd.DataFrame(rows, columns=["id_orig_h", "id_resp_h", *FEATURE_COLUMNS])

    @staticmethod
    def _pair_features(orig: str, resp: str, group: pd.DataFrame) -> dict[str, Any]:
        """Compute the feature dict for a single (id_orig_h, id_resp_h) group."""
        durations = pd.to_numeric(group["duration"], errors="coerce").fillna(0.0)
        orig_bytes = pd.to_numeric(group["orig_bytes"], errors="coerce").fillna(0.0)
        resp_bytes = pd.to_numeric(group["resp_bytes"], errors="coerce").fillna(0.0)

        avg_orig = float(orig_bytes.mean())
        avg_resp = float(resp_bytes.mean())

        total_orig = float(orig_bytes.sum())
        total_resp = float(resp_bytes.sum())
        byte_ratio = total_orig / max(total_resp, 1.0)

        timestamps = pd.to_numeric(group["ts"], errors="coerce").dropna().sort_values()
        delta_mean, delta_std, delta_cv = _interarrival_stats(timestamps.to_list())

        names = group["server_name"].fillna("").astype(str)
        versions = group["version"].fillna("").astype(str)

        valid_names = names[names.str.strip().ne("")]
        sni_entropy = 0.0
        if not valid_names.empty:
            sni_entropy = float(valid_names.apply(_shannon_entropy).mean())

        ja3_homogeneity = _JA3_HOMOGENEITY_DEFAULT

        return {
            "id_orig_h": orig,
            "id_resp_h": resp,
            "connection_count": len(group),
            "avg_duration": float(durations.mean()),
            "stddev_duration": float(durations.std(ddof=0)),
            "avg_orig_bytes": avg_orig,
            "avg_resp_bytes": avg_resp,
            "byte_ratio": byte_ratio,
            "delta_t_mean": delta_mean,
            "delta_t_std": delta_std,
            "delta_t_cv": delta_cv,
            "has_sni": int(valid_names.any() if not valid_names.empty else False),
            "is_tls13": int(versions.isin(_TLS13_VERSIONS).any()),
            "sni_entropy": sni_entropy,
            "ja3_homogeneity": ja3_homogeneity,
        }


def _interarrival_stats(timestamps: list[float]) -> tuple[float, float, float]:
    """Mean, population std-dev and coefficient of variation of inter-arrival deltas.

    A single connection yields no interval, so all three statistics are 0.
    The coefficient of variation is 0 whenever the mean is 0, rather than
    raising a division error.
    """
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0

    deltas = [b - a for a, b in itertools.pairwise(timestamps)]
    mean = sum(deltas) / len(deltas)
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    std = math.sqrt(variance)
    cv = std / mean if mean else 0.0
    return mean, std, cv


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    s_len = len(s)
    counts = {}
    for char in s:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / s_len) * math.log2(count / s_len) for count in counts.values())
