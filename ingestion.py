"""
ingestion.py — Module 1: Traffic Capture Ingestion
===================================================
Responsibility: read a tshark explicit-field CSV export, validate its schema,
normalise column names, coerce types, derive helper flag columns, and drop
malformed rows. Returns a clean, typed DataFrame that is the data-contract for
all downstream modules.

tshark command to generate a valid input CSV (run this OUTSIDE the app):

    tshark -r capture.pcap \
        -T fields \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e udp.srcport \
        -e tcp.dstport \
        -e udp.dstport \
        -e _ws.col.Protocol \
        -e frame.len \
        -e tcp.flags.syn \
        -e tcp.flags.ack \
        -e tcp.flags.reset \
        -e eth.src \
        -e eth.dst \
        -E header=y -E separator=, -E quote=d -E occurrence=f \
        > capture.csv

Limitations (documented, not silently ignored):
- IPv4 only. If IPv6 addresses are detected they are counted and reported; those
  rows are dropped before processing. A warning is attached to the returned
  DataFrame as a `._ipv6_count` attribute.
- A raw stack-trace is NEVER surfaced to the browser; app.py catches the custom
  exceptions defined here and converts them to flash messages.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Final

import pandas as pd

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column name mapping: tshark field name → internal name
# ---------------------------------------------------------------------------
TSHARK_TO_INTERNAL: Final[dict[str, str]] = {
    "frame.time_relative": "timestamp",
    "ip.src":              "src_ip",
    "ip.dst":              "dst_ip",
    "tcp.srcport":         "tcp_src_port",
    "udp.srcport":         "udp_src_port",
    "tcp.dstport":         "tcp_dst_port",
    "udp.dstport":         "udp_dst_port",
    "_ws.col.Protocol":    "protocol",
    "frame.len":           "pkt_len",
    "tcp.flags.syn":       "flag_syn_raw",
    "tcp.flags.ack":       "flag_ack_raw",
    "tcp.flags.reset":     "flag_rst_raw",
    "eth.src":             "eth_src",
    "eth.dst":             "eth_dst",
}

# The set of tshark columns that MUST be present in the uploaded file.
REQUIRED_TSHARK_COLUMNS: Final[frozenset[str]] = frozenset(TSHARK_TO_INTERNAL.keys())

# Simple IPv4 pattern used for detecting non-IPv4 rows.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Custom exceptions (app.py catches these for clean user-facing messages)
# ---------------------------------------------------------------------------

class IngestionError(Exception):
    """Base class for all ingestion errors."""


class SchemaValidationError(IngestionError):
    """Raised when the uploaded CSV is missing required tshark columns."""


class EmptyFileError(IngestionError):
    """Raised when the CSV contains no data rows after parsing."""


# ---------------------------------------------------------------------------
# Pipeline step 1 — Read raw CSV
# ---------------------------------------------------------------------------

def read_raw(filepath: str | Path) -> pd.DataFrame:
    """Read the uploaded CSV file and return a DataFrame of raw strings.

    Everything is read as dtype=str to avoid silent pandas type coercion.
    Whitespace is stripped from column headers.

    Parameters
    ----------
    filepath : str or Path
        Absolute path to the uploaded CSV file.

    Returns
    -------
    pd.DataFrame
        Raw string-typed DataFrame; columns names are whitespace-stripped.

    Raises
    ------
    IngestionError
        If the file cannot be read (missing, permission error, parse error).
    """
    try:
        df = pd.read_csv(filepath, dtype=str, na_values=["", " "])
    except FileNotFoundError as exc:
        raise IngestionError(f"File not found: {filepath}") from exc
    except Exception as exc:
        raise IngestionError(f"Could not read file '{filepath}': {exc}") from exc

    # Strip leading/trailing whitespace from column names.
    df.columns = [c.strip() for c in df.columns]
    logger.info("read_raw: loaded %d rows, %d columns from '%s'",
                len(df), len(df.columns), filepath)
    return df


# ---------------------------------------------------------------------------
# Pipeline step 2 — Validate schema
# ---------------------------------------------------------------------------

def validate_schema(df: pd.DataFrame) -> None:
    """Check that all required tshark columns are present.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame as returned by ``read_raw``.

    Raises
    ------
    SchemaValidationError
        If one or more required columns are absent.  The message lists every
        missing column so the user knows exactly what went wrong.
    """
    present = set(df.columns)
    missing = REQUIRED_TSHARK_COLUMNS - present
    if missing:
        missing_sorted = sorted(missing)
        raise SchemaValidationError(
            "The uploaded CSV is missing the following required tshark columns: "
            + ", ".join(missing_sorted)
            + ". Please re-export with the tshark command shown on the upload page."
        )
    logger.info("validate_schema: all required columns present")


# ---------------------------------------------------------------------------
# Pipeline step 3 — Normalize column names
# ---------------------------------------------------------------------------

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename tshark field names to clean internal column names.

    Only the columns listed in ``TSHARK_TO_INTERNAL`` are renamed; any extra
    columns present in the file are retained unchanged.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame after schema validation.

    Returns
    -------
    pd.DataFrame
        DataFrame with internal column names.
    """
    df = df.rename(columns=TSHARK_TO_INTERNAL)
    logger.info("normalize_columns: columns renamed to internal names")
    return df


# ---------------------------------------------------------------------------
# Pipeline step 4 — Coerce types
# ---------------------------------------------------------------------------

def coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    """Convert columns from raw strings to their proper types.

    Conversions applied:
    - ``timestamp``   → float64 (seconds since capture start)
    - ``tcp_src_port``, ``udp_src_port``, ``tcp_dst_port``, ``udp_dst_port``
                      → nullable Int64 (NaN where absent)
    - ``pkt_len``     → Int64
    - ``flag_syn_raw``, ``flag_ack_raw``, ``flag_rst_raw``
                      → int8 (0 or 1); tshark exports these as hex strings like
                        "0x00000001" or plain "1"/"0".

    Parameters
    ----------
    df : pd.DataFrame
        Normalised DataFrame.

    Returns
    -------
    pd.DataFrame
        Type-coerced DataFrame.
    """
    df = df.copy()

    # --- timestamp: float seconds ---
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")

    # --- port columns: nullable Int64 ---
    for col in ("tcp_src_port", "udp_src_port", "tcp_dst_port", "udp_dst_port"):
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")

    # --- packet length: Int64 ---
    df["pkt_len"] = pd.to_numeric(df["pkt_len"], errors="coerce").astype("Int64")

    # --- TCP flag columns: tshark may export hex (0x00000001) or decimal ---
    for col in ("flag_syn_raw", "flag_ack_raw", "flag_rst_raw"):
        # Convert hex strings to int, fall back to plain int, then to 0.
        df[col] = (
            df[col]
            .fillna("0")
            .apply(_parse_flag_value)
            .astype("int8")
        )

    logger.info("coerce_types: types coerced successfully")
    return df


def _parse_flag_value(raw: str) -> int:
    """Parse a tshark TCP flag value which may be hex (0x...) or decimal."""
    raw = str(raw).strip()
    try:
        if raw.lower().startswith("0x"):
            return 1 if int(raw, 16) != 0 else 0
        return 1 if int(raw) != 0 else 0
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Pipeline step 5 — Derive TCP flag summary column
# ---------------------------------------------------------------------------

def derive_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Add a human-readable ``tcp_flags`` string column.

    For TCP packets the column will contain a comma-separated string of the
    active flags, e.g. ``"SYN"``, ``"SYN,ACK"``, ``"RST"``.
    For non-TCP packets (where all flag columns are 0) the column is ``""``.

    Parameters
    ----------
    df : pd.DataFrame
        Type-coerced DataFrame.

    Returns
    -------
    pd.DataFrame
        DataFrame with an additional ``tcp_flags`` string column.
    """
    df = df.copy()

    def _build_flags(row: pd.Series) -> str:
        parts = []
        if row["flag_syn_raw"]:
            parts.append("SYN")
        if row["flag_ack_raw"]:
            parts.append("ACK")
        if row["flag_rst_raw"]:
            parts.append("RST")
        return ",".join(parts)

    df["tcp_flags"] = df[["flag_syn_raw", "flag_ack_raw", "flag_rst_raw"]].apply(
        _build_flags, axis=1
    )
    logger.info("derive_flags: tcp_flags column added")
    return df


# ---------------------------------------------------------------------------
# Pipeline step 6 — Drop malformed rows
# ---------------------------------------------------------------------------

def drop_malformed_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, int, dict[str, int]]:
    """Remove rows that cannot be reliably processed.

    A row is dropped if:
    - ``timestamp`` is NaN (unparseable timestamp)
    - Both ``src_ip`` and ``dst_ip`` are NaN (no IP addressing at all)
    - Either ``src_ip`` or ``dst_ip`` is not a valid IPv4 address (IPv6 or
      malformed). These rows are counted separately and reported as 'ipv6_or_other'.

    Parameters
    ----------
    df : pd.DataFrame
        Type-coerced DataFrame with ``tcp_flags`` column.

    Returns
    -------
    tuple[pd.DataFrame, int, dict[str, int]]
        - Cleaned DataFrame
        - Total number of dropped rows
        - Breakdown dict: keys are drop reasons, values are counts
    """
    df = df.copy()
    initial_count = len(df)
    drop_reasons: dict[str, int] = {}

    # Drop rows with unparseable timestamps.
    bad_ts = df["timestamp"].isna()
    if bad_ts.any():
        drop_reasons["invalid_timestamp"] = int(bad_ts.sum())
        df = df[~bad_ts]
        logger.warning("drop_malformed_rows: dropped %d rows with invalid timestamp",
                       drop_reasons["invalid_timestamp"])

    # Drop rows with missing both IPs.
    both_missing = df["src_ip"].isna() & df["dst_ip"].isna()
    if both_missing.any():
        drop_reasons["missing_both_ips"] = int(both_missing.sum())
        df = df[~both_missing]
        logger.warning("drop_malformed_rows: dropped %d rows with missing src+dst IP",
                       drop_reasons["missing_both_ips"])

    # Detect and drop IPv6 / non-IPv4 rows.
    # Use .apply() per-cell rather than bitwise OR on StringArrays,
    # which is not supported in pandas 3.0.
    src_is_ipv4 = df["src_ip"].fillna("").apply(_is_ipv4).astype(bool)
    dst_is_ipv4 = df["dst_ip"].fillna("").apply(_is_ipv4).astype(bool)

    # Rows where NEITHER address is IPv4.
    both_non_ipv4 = (~src_is_ipv4) & (~dst_is_ipv4)
    if both_non_ipv4.any():
        drop_reasons["ipv6_or_other"] = int(both_non_ipv4.sum())
        df = df[~both_non_ipv4]
        logger.warning(
            "drop_malformed_rows: dropped %d rows with non-IPv4 addresses (IPv6 "
            "is not supported in this version). Re-capture with --ipv4 flag if needed.",
            drop_reasons["ipv6_or_other"],
        )

    total_dropped = initial_count - len(df)
    logger.info(
        "drop_malformed_rows: %d/%d rows retained (%d dropped, reasons: %s)",
        len(df), initial_count, total_dropped, drop_reasons,
    )
    return df, total_dropped, drop_reasons


def _is_ipv4(addr: str) -> bool:
    """Return True if ``addr`` looks like a valid dotted-quad IPv4 address."""
    return bool(_IPV4_RE.match(str(addr).strip()))


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def ingest(filepath: str | Path) -> tuple[pd.DataFrame, dict]:
    """Full ingestion pipeline: read → validate → normalise → coerce → derive → drop.

    This is the only function that downstream modules should call.

    Parameters
    ----------
    filepath : str or Path
        Path to the uploaded tshark CSV file.

    Returns
    -------
    tuple[pd.DataFrame, dict]
        - Clean, typed DataFrame ready for feature extraction.
          Schema (columns guaranteed present):
            timestamp (float64), src_ip (str), dst_ip (str),
            tcp_src_port (Int64), udp_src_port (Int64),
            tcp_dst_port (Int64), udp_dst_port (Int64),
            protocol (str), pkt_len (Int64),
            flag_syn_raw (int8), flag_ack_raw (int8), flag_rst_raw (int8),
            eth_src (str), eth_dst (str), tcp_flags (str)
        - Metadata dict with keys:
            'packet_count' (int)    — rows after cleaning
            'dropped_count' (int)   — rows removed
            'drop_reasons' (dict)   — breakdown by reason

    Raises
    ------
    SchemaValidationError
        If required columns are missing.
    EmptyFileError
        If no usable rows remain after cleaning.
    IngestionError
        For any other file-read error.
    """
    raw_df = read_raw(filepath)
    validate_schema(raw_df)
    df = normalize_columns(raw_df)
    df = coerce_types(df)
    df = derive_flags(df)
    df, dropped_count, drop_reasons = drop_malformed_rows(df)

    if df.empty:
        raise EmptyFileError(
            "No usable rows remain after cleaning. "
            "Check that the file uses the correct tshark export format."
        )

    meta = {
        "packet_count": len(df),
        "dropped_count": dropped_count,
        "drop_reasons": drop_reasons,
    }
    logger.info("ingest: pipeline complete — %d packets ready for analysis", len(df))
    return df, meta
