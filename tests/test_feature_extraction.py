"""
test_feature_extraction.py — Unit tests for Module 2: feature_extraction.py
=============================================================================
Run with:  python -m pytest tests/test_feature_extraction.py -v
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature_extraction import (
    WINDOW_TYPE_FULL,
    WINDOW_TYPE_SHORT,
    extract_features,
    _extract_short_window_features,
    _extract_full_session_features,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal typed DataFrame matching ingestion output schema."""
    defaults = {
        "timestamp": 0.0,
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "tcp_src_port": 1234,
        "udp_src_port": pd.NA,
        "tcp_dst_port": 80,
        "udp_dst_port": pd.NA,
        "protocol": "TCP",
        "pkt_len": 74,
        "flag_syn_raw": 0,
        "flag_ack_raw": 0,
        "flag_rst_raw": 0,
        "eth_src": "aa:bb:cc:00:00:01",
        "eth_dst": "aa:bb:cc:00:00:02",
        "tcp_flags": "",
    }
    records = []
    for row in rows:
        r = dict(defaults)
        r.update(row)
        records.append(r)
    df = pd.DataFrame(records)
    # Coerce to expected types (light-weight; enough for feature extraction tests).
    df["timestamp"] = df["timestamp"].astype(float)
    df["pkt_len"] = pd.to_numeric(df["pkt_len"]).astype("Int64")
    df["flag_syn_raw"] = df["flag_syn_raw"].astype("int8")
    df["flag_ack_raw"] = df["flag_ack_raw"].astype("int8")
    df["flag_rst_raw"] = df["flag_rst_raw"].astype("int8")
    df["tcp_dst_port"] = pd.to_numeric(df["tcp_dst_port"], errors="coerce").astype("Int64")
    df["udp_dst_port"] = pd.to_numeric(df["udp_dst_port"], errors="coerce").astype("Int64")
    return df


# ---------------------------------------------------------------------------
# Tests — extract_features (end-to-end)
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def test_happy_path_returns_dataframe(self):
        df = _make_packet_df([
            {"timestamp": 0.5, "flag_syn_raw": 1},
            {"timestamp": 1.0, "flag_ack_raw": 1},
        ])
        feat = extract_features(df)
        assert isinstance(feat, pd.DataFrame)
        assert len(feat) > 0

    def test_empty_input_returns_empty(self):
        df = pd.DataFrame()
        feat = extract_features(df)
        assert feat.empty

    def test_both_window_types_present(self):
        df = _make_packet_df([
            {"timestamp": 0.5},
            {"timestamp": 5.0},
        ])
        feat = extract_features(df)
        types = set(feat["window_type"].unique())
        assert WINDOW_TYPE_SHORT in types
        assert WINDOW_TYPE_FULL in types

    def test_required_columns_present(self):
        df = _make_packet_df([{"timestamp": 0.0}])
        feat = extract_features(df)
        required = [
            "src_ip", "dst_ip", "window_type", "window_start", "window_end",
            "packet_count", "byte_volume", "packet_rate", "unique_dst_ports",
            "duration", "syn_count", "ack_count", "rst_count", "syn_ack_ratio",
            "tcp_frac", "udp_frac", "icmp_frac", "other_frac",
        ]
        for col in required:
            assert col in feat.columns, f"Missing column: {col}"


# ---------------------------------------------------------------------------
# Tests — short-window features
# ---------------------------------------------------------------------------

class TestShortWindowFeatures:
    def test_syn_flood_counted_correctly(self):
        """25 SYN packets in the same 10-second window should yield syn_count=25."""
        rows = [
            {"timestamp": 0.0 + i * 0.3, "flag_syn_raw": 1, "flag_ack_raw": 0}
            for i in range(25)
        ]
        df = _make_packet_df(rows)
        feat = _extract_short_window_features(df)
        # All packets fall in bucket 0 (timestamps 0–7.2 seconds).
        row = feat.iloc[0]
        assert row["syn_count"] == 25
        assert row["ack_count"] == 0
        # syn_ack_ratio = 25 / (0 + 1) = 25.0
        assert abs(row["syn_ack_ratio"] - 25.0) < 1e-6

    def test_packets_spanning_two_windows_split_correctly(self):
        """Packets at t=5 and t=15 should fall in different 10-sec buckets."""
        df = _make_packet_df([
            {"timestamp": 5.0},
            {"timestamp": 15.0},
        ])
        feat = _extract_short_window_features(df)
        assert len(feat) == 2, "Expected two separate window rows"
        assert feat["packet_count"].sum() == 2

    def test_unique_dst_ports(self):
        """Contacts to 5 distinct ports should yield unique_dst_ports=5."""
        rows = [
            {"timestamp": float(i), "tcp_dst_port": 80 + i}
            for i in range(5)
        ]
        df = _make_packet_df(rows)
        feat = _extract_short_window_features(df)
        assert feat.iloc[0]["unique_dst_ports"] == 5

    def test_byte_volume_sum(self):
        rows = [{"timestamp": float(i), "pkt_len": 100} for i in range(3)]
        df = _make_packet_df(rows)
        feat = _extract_short_window_features(df)
        assert feat.iloc[0]["byte_volume"] == 300


# ---------------------------------------------------------------------------
# Tests — full-session features
# ---------------------------------------------------------------------------

class TestFullSessionFeatures:
    def test_single_packet_flow(self):
        """A single-packet flow should have duration=0, packet_rate > 0."""
        df = _make_packet_df([{"timestamp": 5.0}])
        feat = _extract_full_session_features(df)
        assert len(feat) == 1
        assert feat.iloc[0]["packet_count"] == 1
        assert feat.iloc[0]["duration"] == 0.0

    def test_two_directed_flows_are_separate(self):
        """A→B and B→A should produce separate feature rows."""
        df = _make_packet_df([
            {"timestamp": 0.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            {"timestamp": 1.0, "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1"},
        ])
        feat = _extract_full_session_features(df)
        assert len(feat) == 2

    def test_protocol_fractions_sum_to_one(self):
        rows = [
            {"timestamp": 0.0, "protocol": "TCP"},
            {"timestamp": 1.0, "protocol": "UDP"},
            {"timestamp": 2.0, "protocol": "ICMP"},
            {"timestamp": 3.0, "protocol": "OTHER"},
        ]
        df = _make_packet_df(rows)
        feat = _extract_full_session_features(df)
        row = feat.iloc[0]
        total = row["tcp_frac"] + row["udp_frac"] + row["icmp_frac"] + row["other_frac"]
        assert abs(total - 1.0) < 1e-9

    def test_syn_ack_ratio_avoids_divide_by_zero(self):
        """Zero ACKs should not raise ZeroDivisionError — ratio = syn / 1."""
        df = _make_packet_df([{"timestamp": 0.0, "flag_syn_raw": 1, "flag_ack_raw": 0}])
        feat = _extract_full_session_features(df)
        assert feat.iloc[0]["syn_ack_ratio"] == 1.0  # 1 / (0 + 1)
