"""
test_rule_engine.py — Unit tests for Module 3: rule_engine.py
==============================================================
Run with:  python -m pytest tests/test_rule_engine.py -v
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from rule_engine import (
    SYN_FLOOD_MIN_SYN_COUNT,
    SYN_FLOOD_RATIO_THRESHOLD,
    FAST_SCAN_PORT_THRESHOLD,
    SLOW_SCAN_PORT_THRESHOLD,
    detect_arp_spoofing,
    detect_fast_port_scan,
    detect_slow_port_scan,
    detect_syn_flood,
    run_rules,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _feature_row(**kwargs) -> dict:
    """Build a feature-table row with sensible defaults."""
    defaults = {
        "src_ip":        "192.168.1.1",
        "dst_ip":        "10.0.0.1",
        "window_type":   "short",
        "window_start":  0.0,
        "window_end":    10.0,
        "packet_count":  1,
        "byte_volume":   74,
        "packet_rate":   0.1,
        "unique_dst_ports": 1,
        "duration":      1.0,
        "syn_count":     0,
        "ack_count":     0,
        "rst_count":     0,
        "syn_ack_ratio": 0.0,
        "tcp_frac":      1.0,
        "udp_frac":      0.0,
        "icmp_frac":     0.0,
        "other_frac":    0.0,
    }
    defaults.update(kwargs)
    return defaults


def _make_feature_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def _make_packet_df(rows: list[dict]) -> pd.DataFrame:
    defaults = {
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "eth_src": "aa:bb:cc:dd:ee:01",
        "eth_dst": "aa:bb:cc:dd:ee:02",
        "timestamp": 0.0,
        "pkt_len": 74,
        "flag_syn_raw": 0,
        "flag_ack_raw": 0,
        "flag_rst_raw": 0,
        "protocol": "TCP",
    }
    records = []
    for row in rows:
        r = dict(defaults)
        r.update(row)
        records.append(r)
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Tests — detect_syn_flood
# ---------------------------------------------------------------------------

class TestDetectSynFlood:
    def test_clear_syn_flood_is_flagged(self):
        """High ratio + sufficient SYN count should raise a flag."""
        row = _feature_row(
            syn_count=100, ack_count=5,
            syn_ack_ratio=100 / 6,  # ~16.7 > 5.0
            window_type="short",
        )
        feat = _make_feature_df([row])
        flags = detect_syn_flood(feat)
        assert len(flags) == 1
        assert flags[0]["threat_type"] == "SYN Flood"
        assert "SYN/ACK ratio" in flags[0]["reason"]

    def test_below_min_syn_count_not_flagged(self):
        """Even with high ratio, too few SYNs should NOT be flagged."""
        row = _feature_row(
            syn_count=SYN_FLOOD_MIN_SYN_COUNT - 1,
            ack_count=0,
            syn_ack_ratio=float(SYN_FLOOD_MIN_SYN_COUNT - 1),
            window_type="short",
        )
        feat = _make_feature_df([row])
        flags = detect_syn_flood(feat)
        assert len(flags) == 0

    def test_below_ratio_threshold_not_flagged(self):
        """Normal SYN/ACK ratio should not be flagged."""
        row = _feature_row(
            syn_count=20, ack_count=18,
            syn_ack_ratio=20 / 19,  # ≈ 1.05 < 5.0
            window_type="short",
        )
        feat = _make_feature_df([row])
        flags = detect_syn_flood(feat)
        assert len(flags) == 0

    def test_full_session_window_not_evaluated(self):
        """SYN flood rule should only look at short-window rows."""
        row = _feature_row(
            syn_count=200, ack_count=0,
            syn_ack_ratio=200.0,
            window_type="full_session",  # <-- should be ignored
        )
        feat = _make_feature_df([row])
        flags = detect_syn_flood(feat)
        assert len(flags) == 0

    def test_empty_feature_df_returns_empty(self):
        flags = detect_syn_flood(pd.DataFrame())
        assert flags == []


# ---------------------------------------------------------------------------
# Tests — detect_fast_port_scan
# ---------------------------------------------------------------------------

class TestDetectFastPortScan:
    def test_exceeds_threshold_flagged(self):
        row = _feature_row(
            unique_dst_ports=FAST_SCAN_PORT_THRESHOLD,
            window_type="short",
        )
        feat = _make_feature_df([row])
        flags = detect_fast_port_scan(feat)
        assert len(flags) == 1
        assert flags[0]["threat_type"] == "Port Scan (Fast)"

    def test_below_threshold_not_flagged(self):
        row = _feature_row(
            unique_dst_ports=FAST_SCAN_PORT_THRESHOLD - 1,
            window_type="short",
        )
        feat = _make_feature_df([row])
        flags = detect_fast_port_scan(feat)
        assert len(flags) == 0

    def test_full_session_rows_ignored(self):
        row = _feature_row(
            unique_dst_ports=100,
            window_type="full_session",
        )
        feat = _make_feature_df([row])
        flags = detect_fast_port_scan(feat)
        assert len(flags) == 0


# ---------------------------------------------------------------------------
# Tests — detect_slow_port_scan
# ---------------------------------------------------------------------------

class TestDetectSlowPortScan:
    def test_slow_scan_flagged_when_not_in_fast_scan(self):
        row = _feature_row(
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            unique_dst_ports=SLOW_SCAN_PORT_THRESHOLD,
            window_type="full_session",
        )
        feat = _make_feature_df([row])
        flags = detect_slow_port_scan(feat, fast_scan_flags=[])
        assert len(flags) == 1
        assert flags[0]["threat_type"] == "Port Scan (Slow)"

    def test_slow_scan_suppressed_if_already_caught_by_fast_scan(self):
        """If fast scan already flagged the same pair, slow scan must NOT re-flag."""
        row = _feature_row(
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            unique_dst_ports=SLOW_SCAN_PORT_THRESHOLD,
            window_type="full_session",
        )
        feat = _make_feature_df([row])
        # Simulate an existing fast-scan flag for the same (src, dst).
        fast_flag = {
            "threat_type": "Port Scan (Fast)",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "reason": "...",
            "layer": "rule-based",
            "window_start": 0.0,
            "window_end": 10.0,
        }
        flags = detect_slow_port_scan(feat, fast_scan_flags=[fast_flag])
        assert len(flags) == 0

    def test_below_threshold_not_flagged(self):
        row = _feature_row(
            unique_dst_ports=SLOW_SCAN_PORT_THRESHOLD - 1,
            window_type="full_session",
        )
        feat = _make_feature_df([row])
        flags = detect_slow_port_scan(feat, fast_scan_flags=[])
        assert len(flags) == 0


# ---------------------------------------------------------------------------
# Tests — detect_arp_spoofing
# ---------------------------------------------------------------------------

class TestDetectArpSpoofing:
    def test_single_mac_per_ip_not_flagged(self):
        df = _make_packet_df([
            {"src_ip": "192.168.1.1", "eth_src": "aa:bb:cc:dd:ee:01"},
            {"src_ip": "192.168.1.1", "eth_src": "aa:bb:cc:dd:ee:01"},
        ])
        flags = detect_arp_spoofing(df)
        assert len(flags) == 0

    def test_two_macs_for_same_ip_flagged(self):
        df = _make_packet_df([
            {"src_ip": "192.168.1.1", "eth_src": "aa:bb:cc:dd:ee:01"},
            {"src_ip": "192.168.1.1", "eth_src": "ff:ee:dd:cc:bb:aa"},
        ])
        flags = detect_arp_spoofing(df)
        assert len(flags) == 1
        assert flags[0]["threat_type"] == "ARP Spoofing"
        assert flags[0]["src_ip"] == "192.168.1.1"
        assert flags[0]["dst_ip"] is None  # ARP flags have no dst_ip

    def test_empty_df_returns_empty(self):
        flags = detect_arp_spoofing(pd.DataFrame(columns=["src_ip", "eth_src"]))
        assert flags == []


# ---------------------------------------------------------------------------
# Tests — run_rules (integration)
# ---------------------------------------------------------------------------

class TestRunRules:
    def test_empty_inputs_return_empty(self):
        flags = run_rules(pd.DataFrame(), pd.DataFrame())
        assert flags == []

    def test_returns_list_of_dicts_with_required_keys(self):
        feat = _make_feature_df([
            _feature_row(
                syn_count=100, ack_count=0,
                syn_ack_ratio=100.0,
                window_type="short",
            )
        ])
        pkt = _make_packet_df([{"src_ip": "192.168.1.1", "eth_src": "aa:bb:cc"}])
        flags = run_rules(feat, pkt)
        required_keys = {"threat_type", "src_ip", "dst_ip", "reason", "layer",
                         "window_start", "window_end"}
        for f in flags:
            assert required_keys.issubset(f.keys()), f"Missing keys in flag: {f}"
