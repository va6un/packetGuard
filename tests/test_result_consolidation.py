"""
test_result_consolidation.py — Unit tests for Module 5: result_consolidation.py
================================================================================
Run with:  python -m pytest tests/test_result_consolidation.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from result_consolidation import consolidate, _merge_flags, _windows_overlap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_flag(src="1.1.1.1", dst="2.2.2.2", threat="SYN Flood",
               ws=0.0, we=10.0) -> dict:
    return {
        "threat_type": threat, "src_ip": src, "dst_ip": dst,
        "reason": "Rule reason.", "layer": "rule-based",
        "window_start": ws, "window_end": we,
    }


def _ml_flag(src="1.1.1.1", dst="2.2.2.2", threat="Anomalous Flow",
             ws=0.0, we=10.0) -> dict:
    return {
        "threat_type": threat, "src_ip": src, "dst_ip": dst,
        "reason": "ML reason.", "layer": "machine-learning",
        "window_start": ws, "window_end": we,
    }


# ---------------------------------------------------------------------------
# Tests — _windows_overlap
# ---------------------------------------------------------------------------

class TestWindowsOverlap:
    def test_overlapping_windows(self):
        f1 = {"window_start": 0.0, "window_end": 10.0}
        f2 = {"window_start": 5.0, "window_end": 15.0}
        assert _windows_overlap(f1, f2) is True

    def test_adjacent_windows_overlap(self):
        f1 = {"window_start": 0.0, "window_end": 10.0}
        f2 = {"window_start": 10.0, "window_end": 20.0}
        assert _windows_overlap(f1, f2) is True  # [0,10] ∩ [10,20] = {10}

    def test_non_overlapping_windows(self):
        f1 = {"window_start": 0.0, "window_end": 5.0}
        f2 = {"window_start": 6.0, "window_end": 15.0}
        assert _windows_overlap(f1, f2) is False

    def test_missing_window_treated_as_overlap(self):
        f1 = {"window_start": None, "window_end": None}
        f2 = {"window_start": 0.0, "window_end": 10.0}
        assert _windows_overlap(f1, f2) is True

    def test_both_missing_windows_treated_as_overlap(self):
        f1 = {"window_start": None, "window_end": None}
        f2 = {"window_start": None, "window_end": None}
        assert _windows_overlap(f1, f2) is True


# ---------------------------------------------------------------------------
# Tests — _merge_flags
# ---------------------------------------------------------------------------

class TestMergeFlags:
    def test_matching_pair_merged_into_one(self):
        """Same (src, dst) + overlapping window → one merged entry."""
        rule = [_rule_flag()]
        ml   = [_ml_flag()]
        merged = _merge_flags(rule, ml)
        assert len(merged) == 1
        assert merged[0]["layer"] == "rule-based + machine-learning"

    def test_ml_confirmation_appended_to_reason(self):
        rule = [_rule_flag()]
        ml   = [_ml_flag()]
        merged = _merge_flags(rule, ml)
        assert "ML engine independently confirmed" in merged[0]["reason"]

    def test_non_overlapping_window_produces_two_entries(self):
        """Same pair but non-overlapping windows → two separate entries."""
        rule = [_rule_flag(ws=0.0, we=5.0)]
        ml   = [_ml_flag(ws=20.0, we=30.0)]
        merged = _merge_flags(rule, ml)
        assert len(merged) == 2

    def test_different_ips_not_merged(self):
        rule = [_rule_flag(src="1.1.1.1", dst="2.2.2.2")]
        ml   = [_ml_flag(src="3.3.3.3", dst="4.4.4.4")]
        merged = _merge_flags(rule, ml)
        assert len(merged) == 2
        layers = {m["layer"] for m in merged}
        assert "rule-based" in layers
        assert "machine-learning" in layers

    def test_empty_inputs_return_empty(self):
        merged = _merge_flags([], [])
        assert merged == []

    def test_only_ml_flags_returned_standalone(self):
        ml = [_ml_flag()]
        merged = _merge_flags([], ml)
        assert len(merged) == 1
        assert merged[0]["layer"] == "machine-learning"

    def test_rule_flags_unchanged_when_no_ml(self):
        rule = [_rule_flag()]
        merged = _merge_flags(rule, [])
        assert len(merged) == 1
        assert merged[0]["layer"] == "rule-based"


# ---------------------------------------------------------------------------
# Tests — consolidate (public entrypoint)
# ---------------------------------------------------------------------------

class TestConsolidate:
    def test_empty_inputs_return_empty(self):
        result = consolidate([], [])
        assert result == []

    def test_syn_flood_sorted_before_port_scan(self):
        rule_flags = [
            _rule_flag(src="192.168.1.2", threat="Port Scan (Fast)"),
            _rule_flag(src="192.168.1.1", threat="SYN Flood"),
        ]
        result = consolidate(rule_flags, [])
        assert result[0]["threat_type"] == "SYN Flood"
        assert result[1]["threat_type"] == "Port Scan (Fast)"

    def test_result_has_required_keys(self):
        result = consolidate([_rule_flag()], [_ml_flag(src="9.9.9.9")])
        required = {"threat_type", "src_ip", "dst_ip", "reason", "layer",
                    "window_start", "window_end"}
        for entry in result:
            assert required.issubset(entry.keys())

    def test_merge_and_standalone_combined_correctly(self):
        """One matching pair (merged) + one standalone ML flag."""
        rule_flags = [_rule_flag(src="1.1.1.1", dst="2.2.2.2")]
        ml_flags   = [
            _ml_flag(src="1.1.1.1", dst="2.2.2.2"),  # matches rule → merge
            _ml_flag(src="9.9.9.9", dst="8.8.8.8"),  # standalone
        ]
        result = consolidate(rule_flags, ml_flags)
        # 1 merged + 1 standalone = 2 total
        assert len(result) == 2
        merged_entry = next(r for r in result if r["src_ip"] == "1.1.1.1")
        assert merged_entry["layer"] == "rule-based + machine-learning"
        standalone = next(r for r in result if r["src_ip"] == "9.9.9.9")
        assert standalone["layer"] == "machine-learning"
