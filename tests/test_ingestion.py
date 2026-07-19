"""
test_ingestion.py — Unit tests for Module 1: ingestion.py
==========================================================
Uses small synthetic DataFrames and temporary CSV files — no real capture
files required.  Run with:  python -m pytest tests/test_ingestion.py -v
"""

from __future__ import annotations

import io
import textwrap
from pathlib import Path

import pandas as pd
import pytest

# Add parent directory to path so we can import without installing.
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion import (
    EmptyFileError,
    SchemaValidationError,
    coerce_types,
    derive_flags,
    drop_malformed_rows,
    ingest,
    normalize_columns,
    read_raw,
    validate_schema,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Minimal valid tshark header line.
VALID_HEADER = (
    "frame.time_relative,ip.src,ip.dst,tcp.srcport,udp.srcport,"
    "tcp.dstport,udp.dstport,_ws.col.Protocol,frame.len,"
    "tcp.flags.syn,tcp.flags.ack,tcp.flags.reset,eth.src,eth.dst"
)


def _make_valid_csv_content(rows: list[str]) -> str:
    """Build a minimal valid tshark CSV string."""
    return VALID_HEADER + "\n" + "\n".join(rows) + "\n"


def _write_temp_csv(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "capture.csv"
    p.write_text(content, encoding="utf-8")
    return p


def _minimal_row(
    ts="0.5",
    src="192.168.1.1",
    dst="10.0.0.1",
    tcp_sp="1234",
    udp_sp="",
    tcp_dp="80",
    udp_dp="",
    proto="TCP",
    length="74",
    syn="1",
    ack="0",
    rst="0",
    eth_src="aa:bb:cc:dd:ee:01",
    eth_dst="aa:bb:cc:dd:ee:02",
) -> str:
    return (
        f'"{ts}","{src}","{dst}","{tcp_sp}","{udp_sp}",'
        f'"{tcp_dp}","{udp_dp}","{proto}","{length}",'
        f'"{syn}","{ack}","{rst}","{eth_src}","{eth_dst}"'
    )


# ---------------------------------------------------------------------------
# Tests — read_raw
# ---------------------------------------------------------------------------

class TestReadRaw:
    def test_happy_path(self, tmp_path):
        """Should read a valid CSV without coercing types."""
        content = _make_valid_csv_content([_minimal_row()])
        p = _write_temp_csv(tmp_path, content)
        df = read_raw(str(p))
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        # All values should remain as strings (no type coercion at this stage).
        assert pd.api.types.is_string_dtype(df["frame.time_relative"])

    def test_missing_file_raises_ingestion_error(self):
        """Should raise IngestionError if file does not exist."""
        from ingestion import IngestionError
        with pytest.raises(IngestionError):
            read_raw("/nonexistent/path/capture.csv")

    def test_column_whitespace_stripped(self, tmp_path):
        """Column names with leading/trailing spaces should be stripped."""
        content = " frame.time_relative , ip.src , ip.dst , tcp.srcport , udp.srcport , tcp.dstport , udp.dstport , _ws.col.Protocol , frame.len , tcp.flags.syn , tcp.flags.ack , tcp.flags.reset , eth.src , eth.dst \n"
        content += _minimal_row() + "\n"
        p = _write_temp_csv(tmp_path, content)
        df = read_raw(str(p))
        # Column names should not have spaces.
        assert all(c == c.strip() for c in df.columns)


# ---------------------------------------------------------------------------
# Tests — validate_schema
# ---------------------------------------------------------------------------

class TestValidateSchema:
    def test_happy_path_all_columns_present(self, tmp_path):
        """Should not raise when all required columns are present."""
        content = _make_valid_csv_content([_minimal_row()])
        p = _write_temp_csv(tmp_path, content)
        df = read_raw(str(p))
        validate_schema(df)  # Must not raise.

    def test_missing_column_raises(self):
        """Should raise SchemaValidationError listing all missing columns."""
        df = pd.DataFrame({"ip.src": ["1.2.3.4"], "ip.dst": ["5.6.7.8"]})
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_schema(df)
        # The error message should mention at least one missing column.
        assert "frame.time_relative" in str(exc_info.value)

    def test_empty_dataframe_raises(self):
        """An empty DataFrame (no columns) should raise SchemaValidationError."""
        df = pd.DataFrame()
        with pytest.raises(SchemaValidationError):
            validate_schema(df)


# ---------------------------------------------------------------------------
# Tests — normalize_columns
# ---------------------------------------------------------------------------

class TestNormalizeColumns:
    def test_renames_all_tshark_fields(self, tmp_path):
        content = _make_valid_csv_content([_minimal_row()])
        p = _write_temp_csv(tmp_path, content)
        df = read_raw(str(p))
        df = normalize_columns(df)
        assert "timestamp" in df.columns
        assert "src_ip" in df.columns
        assert "dst_ip" in df.columns
        # Original names should be gone.
        assert "frame.time_relative" not in df.columns
        assert "ip.src" not in df.columns


# ---------------------------------------------------------------------------
# Tests — coerce_types
# ---------------------------------------------------------------------------

class TestCoerceTypes:
    def _make_normalized_df(self, rows: list[str], tmp_path: Path) -> pd.DataFrame:
        content = _make_valid_csv_content(rows)
        p = _write_temp_csv(tmp_path, content)
        df = read_raw(str(p))
        validate_schema(df)
        return normalize_columns(df)

    def test_timestamp_becomes_float(self, tmp_path):
        df = self._make_normalized_df([_minimal_row(ts="1.234")], tmp_path)
        df = coerce_types(df)
        assert df["timestamp"].dtype == float
        assert abs(df["timestamp"].iloc[0] - 1.234) < 1e-9

    def test_ports_become_nullable_int(self, tmp_path):
        df = self._make_normalized_df([_minimal_row(tcp_sp="", udp_sp="5353")], tmp_path)
        df = coerce_types(df)
        assert df["tcp_src_port"].isna().iloc[0]
        assert df["udp_src_port"].iloc[0] == 5353

    def test_hex_flag_parsed_correctly(self, tmp_path):
        """tshark sometimes exports TCP flags as hex strings."""
        df = self._make_normalized_df(
            [_minimal_row(syn="0x00000001", ack="0x00000000", rst="0x00000001")],
            tmp_path,
        )
        df = coerce_types(df)
        assert df["flag_syn_raw"].iloc[0] == 1
        assert df["flag_ack_raw"].iloc[0] == 0
        assert df["flag_rst_raw"].iloc[0] == 1

    def test_pkt_len_is_int(self, tmp_path):
        df = self._make_normalized_df([_minimal_row(length="1500")], tmp_path)
        df = coerce_types(df)
        assert df["pkt_len"].iloc[0] == 1500


# ---------------------------------------------------------------------------
# Tests — derive_flags
# ---------------------------------------------------------------------------

class TestDeriveFlags:
    def _base_df(self, syn, ack, rst) -> pd.DataFrame:
        return pd.DataFrame({
            "flag_syn_raw": [syn],
            "flag_ack_raw": [ack],
            "flag_rst_raw": [rst],
        })

    def test_syn_only(self):
        df = derive_flags(self._base_df(1, 0, 0))
        assert df["tcp_flags"].iloc[0] == "SYN"

    def test_syn_ack(self):
        df = derive_flags(self._base_df(1, 1, 0))
        assert df["tcp_flags"].iloc[0] == "SYN,ACK"

    def test_rst(self):
        df = derive_flags(self._base_df(0, 0, 1))
        assert df["tcp_flags"].iloc[0] == "RST"

    def test_no_flags_empty_string(self):
        df = derive_flags(self._base_df(0, 0, 0))
        assert df["tcp_flags"].iloc[0] == ""


# ---------------------------------------------------------------------------
# Tests — drop_malformed_rows
# ---------------------------------------------------------------------------

class TestDropMalformedRows:
    def _make_df(self, rows: list[dict]) -> pd.DataFrame:
        """Build a minimal post-coerce-types DataFrame."""
        return pd.DataFrame(rows)

    def test_happy_path_no_drops(self):
        df = self._make_df([
            {"timestamp": 1.0, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
             "flag_syn_raw": 1, "flag_ack_raw": 0, "flag_rst_raw": 0},
        ])
        df["tcp_flags"] = "SYN"
        clean, dropped, reasons = drop_malformed_rows(df)
        assert dropped == 0
        assert len(clean) == 1

    def test_nan_timestamp_dropped(self):
        df = self._make_df([
            {"timestamp": float("nan"), "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
             "flag_syn_raw": 1, "flag_ack_raw": 0, "flag_rst_raw": 0},
            {"timestamp": 1.0, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
             "flag_syn_raw": 0, "flag_ack_raw": 1, "flag_rst_raw": 0},
        ])
        df["tcp_flags"] = ["SYN", "ACK"]
        clean, dropped, reasons = drop_malformed_rows(df)
        assert dropped == 1
        assert "invalid_timestamp" in reasons

    def test_both_ips_missing_dropped(self):
        df = self._make_df([
            {"timestamp": 1.0, "src_ip": None, "dst_ip": None,
             "flag_syn_raw": 0, "flag_ack_raw": 0, "flag_rst_raw": 0},
        ])
        df["tcp_flags"] = ""
        clean, dropped, reasons = drop_malformed_rows(df)
        assert dropped == 1
        assert "missing_both_ips" in reasons

    def test_ipv6_addresses_dropped_with_reason(self):
        df = self._make_df([
            {"timestamp": 1.0,
             "src_ip": "2001:db8::1", "dst_ip": "2001:db8::2",
             "flag_syn_raw": 0, "flag_ack_raw": 0, "flag_rst_raw": 0},
        ])
        df["tcp_flags"] = ""
        clean, dropped, reasons = drop_malformed_rows(df)
        assert dropped == 1
        assert "ipv6_or_other" in reasons

    def test_empty_input_returns_empty(self):
        df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip",
                                   "flag_syn_raw", "flag_ack_raw", "flag_rst_raw",
                                   "tcp_flags"])
        clean, dropped, reasons = drop_malformed_rows(df)
        assert len(clean) == 0
        assert dropped == 0


# ---------------------------------------------------------------------------
# Tests — ingest (end-to-end)
# ---------------------------------------------------------------------------

class TestIngest:
    def test_happy_path_sample_csv(self):
        """Full pipeline should work on the synthetic sample capture."""
        sample_path = Path(__file__).parent.parent / "sample_data" / "sample_capture.csv"
        df, meta = ingest(str(sample_path))
        assert len(df) > 0
        assert "timestamp" in df.columns
        assert "src_ip" in df.columns
        assert "tcp_flags" in df.columns
        assert meta["packet_count"] == len(df)

    def test_missing_columns_raises_schema_error(self, tmp_path):
        """Pipeline should raise SchemaValidationError for bad schema files."""
        content = "col_a,col_b\n1,2\n"
        p = tmp_path / "bad.csv"
        p.write_text(content)
        with pytest.raises(SchemaValidationError):
            ingest(str(p))

    def test_all_malformed_rows_raises_empty_file_error(self, tmp_path):
        """If all rows are malformed, ingest should raise EmptyFileError."""
        # All rows have invalid timestamps and no IPs.
        rows = [
            '"not_a_number","","","","","","","TCP","74","0","0","0","aa:bb","cc:dd"',
            '"bad","","","","","","","TCP","74","0","0","0","aa:bb","cc:dd"',
        ]
        content = (
            "frame.time_relative,ip.src,ip.dst,tcp.srcport,udp.srcport,"
            "tcp.dstport,udp.dstport,_ws.col.Protocol,frame.len,"
            "tcp.flags.syn,tcp.flags.ack,tcp.flags.reset,eth.src,eth.dst\n"
        ) + "\n".join(rows) + "\n"
        p = tmp_path / "malformed.csv"
        p.write_text(content)
        with pytest.raises(EmptyFileError):
            ingest(str(p))
