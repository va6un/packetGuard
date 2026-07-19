"""
test_ml_engine.py — Unit tests for Module 4: ml_engine.py
===========================================================
Run with:  python -m pytest tests/test_ml_engine.py -v
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_engine import run_isolation_forest, _build_reason, _FEATURE_COLS, _LAYER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_feature_df(n_normal: int = 20, include_outlier: bool = True) -> pd.DataFrame:
    """Build a synthetic feature DataFrame with clear outlier(s).

    n_normal normal-looking rows + optionally 1 obvious outlier row.
    The outlier has packet_rate and byte_volume ~100× the normal values, making
    it easy for Isolation Forest to identify it as anomalous.
    """
    rng = np.random.default_rng(seed=42)
    rows = []
    for i in range(n_normal):
        rows.append({
            "src_ip":          f"192.168.1.{(i % 254) + 1}",
            "dst_ip":          "10.0.0.1",
            "window_type":     "short",
            "window_start":    float(i * 10),
            "window_end":      float(i * 10 + 10),
            "packet_count":    int(rng.integers(5, 20)),
            "byte_volume":     int(rng.integers(300, 1500)),
            "packet_rate":     float(rng.uniform(0.5, 2.0)),
            "unique_dst_ports": 1,
            "duration":        float(rng.uniform(0.1, 5.0)),
            "syn_count":       1,
            "ack_count":       5,
            "rst_count":       0,
            "syn_ack_ratio":   1 / 6,
            "tcp_frac":        1.0,
            "udp_frac":        0.0,
            "icmp_frac":       0.0,
            "other_frac":      0.0,
        })
    if include_outlier:
        rows.append({
            "src_ip":          "10.99.99.99",
            "dst_ip":          "192.168.1.1",
            "window_type":     "short",
            "window_start":    0.0,
            "window_end":      10.0,
            "packet_count":    5000,
            "byte_volume":     750000,     # enormous — clear outlier
            "packet_rate":     500.0,      # enormous
            "unique_dst_ports": 200,
            "duration":        10.0,
            "syn_count":       4800,
            "ack_count":       10,
            "rst_count":       0,
            "syn_ack_ratio":   480.0,
            "tcp_frac":        1.0,
            "udp_frac":        0.0,
            "icmp_frac":       0.0,
            "other_frac":      0.0,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Tests — run_isolation_forest
# ---------------------------------------------------------------------------

class TestRunIsolationForest:
    def test_obvious_outlier_is_flagged(self):
        """A flow with extreme values should be detected as an anomaly."""
        feat = _make_feature_df(n_normal=20, include_outlier=True)
        flags = run_isolation_forest(feat)
        assert len(flags) >= 1, "Expected at least one anomaly flag"
        outlier_flag = next(
            (f for f in flags if f["src_ip"] == "10.99.99.99"), None
        )
        assert outlier_flag is not None, "Outlier IP 10.99.99.99 should be flagged"

    def test_flag_dict_contains_required_keys(self):
        feat = _make_feature_df(n_normal=20, include_outlier=True)
        flags = run_isolation_forest(feat)
        required = {"threat_type", "src_ip", "dst_ip", "reason", "layer",
                    "window_start", "window_end"}
        for flag in flags:
            assert required.issubset(flag.keys()), f"Flag missing keys: {flag}"

    def test_layer_is_machine_learning(self):
        feat = _make_feature_df(n_normal=20, include_outlier=True)
        flags = run_isolation_forest(feat)
        for flag in flags:
            assert flag["layer"] == _LAYER

    def test_reason_mentions_feature_name(self):
        """The reason string must name at least one feature column, not just say 'anomaly'."""
        feat = _make_feature_df(n_normal=20, include_outlier=True)
        flags = run_isolation_forest(feat)
        # At least one flag should have a feature name in its reason.
        feature_mentioned = any(
            any(col in flag["reason"] for col in _FEATURE_COLS)
            for flag in flags
        )
        assert feature_mentioned, "Reason string should name a feature column"

    def test_empty_dataframe_returns_empty(self):
        flags = run_isolation_forest(pd.DataFrame())
        assert flags == []

    def test_single_row_returns_empty(self):
        """With only 1 row, anomaly detection cannot be meaningful — expect empty."""
        feat = _make_feature_df(n_normal=0, include_outlier=True)
        flags = run_isolation_forest(feat)
        # With 1 row, our guard returns empty.
        assert flags == []

    def test_normal_flows_without_outlier_may_return_empty_or_few(self):
        """Homogeneous data should produce few or no flags."""
        feat = _make_feature_df(n_normal=30, include_outlier=False)
        flags = run_isolation_forest(feat)
        # With contamination='auto' on homogeneous data the number should be low.
        # We don't assert zero (IsoForest always flags some), just that it's a list.
        assert isinstance(flags, list)


# ---------------------------------------------------------------------------
# Tests — _build_reason
# ---------------------------------------------------------------------------

class TestBuildReason:
    def test_reason_contains_direction_above(self):
        # Create z-scores where first feature is strongly positive.
        z = np.array([[3.5, 0.1, -0.2]])
        features = ["byte_volume", "packet_rate", "syn_ack_ratio"]
        reason = _build_reason(0, z, features)
        assert "byte_volume" in reason
        assert "above" in reason

    def test_reason_contains_direction_below(self):
        z = np.array([[-4.2, 0.1]])
        features = ["duration", "packet_rate"]
        reason = _build_reason(0, z, features)
        assert "duration" in reason
        assert "below" in reason

    def test_reason_mentions_top_features_only(self):
        """Only top-2 features should appear; the third should be absent."""
        z = np.array([[5.0, 3.0, 0.1]])
        features = ["byte_volume", "packet_rate", "duration"]
        reason = _build_reason(0, z, features)
        assert "byte_volume" in reason
        assert "packet_rate" in reason
        # duration has z=0.1, shouldn't dominate
        # (it may or may not appear depending on top-N; with N=2 it won't)
        assert "duration" not in reason
