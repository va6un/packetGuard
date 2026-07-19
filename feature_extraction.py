"""
feature_extraction.py — Module 2: Flow-Level Feature Extraction
================================================================
Responsibility: group packets into directed flows and compute per-flow
statistical features across two time granularities.

Flow key:
    Ordered (src_ip, dst_ip) pair — ordered rather than unordered because:
    - SYN flood direction matters (attacker → victim, not symmetric)
    - Port scan direction matters (scanner → targets, not symmetric)
    This is a deliberate design choice; it means A→B and B→A are separate flows.

Time windows:
    SHORT_WINDOW_SEC (10 s):   catches fast, volumetric attacks
    FULL_SESSION:               catches slow, low-rate attacks across the whole
                                capture duration

Output schema (one row per (src_ip, dst_ip, window_type, window_start)):
    src_ip, dst_ip, window_type, window_start, window_end,
    packet_count, byte_volume, packet_rate, unique_dst_ports,
    duration, syn_count, ack_count, rst_count, syn_ack_ratio,
    tcp_frac, udp_frac, icmp_frac, other_frac
"""

from __future__ import annotations

import logging
from typing import Final

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SHORT_WINDOW_SEC: Final[int] = 10   # seconds per short-window bucket
WINDOW_TYPE_SHORT: Final[str] = "short"
WINDOW_TYPE_FULL: Final[str] = "full_session"

# Protocol labels (lower-cased for matching against the 'protocol' column).
_PROTO_TCP: Final[str] = "tcp"
_PROTO_UDP: Final[str] = "udp"
_PROTO_ICMP: Final[str] = "icmp"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _effective_dst_port(df: pd.DataFrame) -> pd.Series:
    """Return the effective destination port (TCP preferred, fall back to UDP).

    tshark exports TCP and UDP ports into separate columns (tcp.dstport,
    udp.dstport).  We combine them into a single 'effective port' column so
    that groupby aggregations can count unique destination ports uniformly.
    """
    # Prefer tcp_dst_port; where it's NA, use udp_dst_port.
    return df["tcp_dst_port"].fillna(df["udp_dst_port"])


def _assign_short_window(df: pd.DataFrame) -> pd.Series:
    """Assign each row to a 10-second window bucket (floor division)."""
    return (df["timestamp"] // SHORT_WINDOW_SEC).astype(int)


def _compute_protocol_fractions(group_df: pd.DataFrame) -> dict[str, float]:
    """Return TCP/UDP/ICMP/other fractions for a group of packets."""
    total = len(group_df)
    if total == 0:
        return {"tcp_frac": 0.0, "udp_frac": 0.0, "icmp_frac": 0.0, "other_frac": 0.0}
    protos = group_df["protocol"].str.lower()
    return {
        "tcp_frac":   (protos == _PROTO_TCP).sum() / total,
        "udp_frac":   (protos == _PROTO_UDP).sum() / total,
        "icmp_frac":  (protos == _PROTO_ICMP).sum() / total,
        "other_frac": (~protos.isin([_PROTO_TCP, _PROTO_UDP, _PROTO_ICMP])).sum() / total,
    }


def _agg_group(group_df: pd.DataFrame, window_type: str,
               window_start: float, window_end: float) -> dict:
    """Compute all features for one (src_ip, dst_ip, window) group.

    This function is called once per group; it is NOT applied row-by-row —
    the calling code uses groupby / apply which operates on sub-DataFrames.
    """
    packet_count = len(group_df)
    byte_volume   = int(group_df["pkt_len"].sum())
    duration      = group_df["timestamp"].max() - group_df["timestamp"].min()
    packet_rate   = packet_count / max(duration, 1e-6)

    eff_port = _effective_dst_port(group_df)
    unique_dst_ports = int(eff_port.dropna().nunique())

    syn_count  = int(group_df["flag_syn_raw"].sum())
    ack_count  = int(group_df["flag_ack_raw"].sum())
    rst_count  = int(group_df["flag_rst_raw"].sum())
    syn_ack_ratio = syn_count / (ack_count + 1)  # +1 avoids divide-by-zero

    proto_fracs = _compute_protocol_fractions(group_df)

    return {
        "window_type":      window_type,
        "window_start":     window_start,
        "window_end":       window_end,
        "packet_count":     packet_count,
        "byte_volume":      byte_volume,
        "packet_rate":      packet_rate,
        "unique_dst_ports": unique_dst_ports,
        "duration":         duration,
        "syn_count":        syn_count,
        "ack_count":        ack_count,
        "rst_count":        rst_count,
        "syn_ack_ratio":    syn_ack_ratio,
        **proto_fracs,
    }


# ---------------------------------------------------------------------------
# Short-window feature extraction (10-second buckets)
# ---------------------------------------------------------------------------

def _extract_short_window_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute features for 10-second time buckets.

    Groups: (src_ip, dst_ip, window_bucket)
    Returns one row per group.
    """
    df = df.copy()
    df["_window_bucket"] = _assign_short_window(df)

    records = []
    for (src_ip, dst_ip, bucket), grp in df.groupby(
        ["src_ip", "dst_ip", "_window_bucket"]
    ):
        window_start = float(bucket * SHORT_WINDOW_SEC)
        window_end   = float((bucket + 1) * SHORT_WINDOW_SEC)
        row = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            **_agg_group(grp, WINDOW_TYPE_SHORT, window_start, window_end),
        }
        records.append(row)

    if not records:
        return pd.DataFrame()

    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Full-session feature extraction
# ---------------------------------------------------------------------------

def _extract_full_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute features across the entire capture duration.

    Groups: (src_ip, dst_ip)
    Returns one row per directed flow.
    """
    session_start = float(df["timestamp"].min())
    session_end   = float(df["timestamp"].max())

    records = []
    for (src_ip, dst_ip), grp in df.groupby(["src_ip", "dst_ip"]):
        row = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            **_agg_group(grp, WINDOW_TYPE_FULL, session_start, session_end),
        }
        records.append(row)

    if not records:
        return pd.DataFrame()

    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute flow-level features for both short-window and full-session views.

    Parameters
    ----------
    df : pd.DataFrame
        Clean, typed packet DataFrame as returned by ``ingestion.ingest()``.

    Returns
    -------
    pd.DataFrame
        Feature table with one row per (src_ip, dst_ip, window_type, window_start).
        Columns: src_ip, dst_ip, window_type, window_start, window_end,
                 packet_count, byte_volume, packet_rate, unique_dst_ports,
                 duration, syn_count, ack_count, rst_count, syn_ack_ratio,
                 tcp_frac, udp_frac, icmp_frac, other_frac.

    Notes
    -----
    Returns an empty DataFrame if the input is empty; callers must handle this.
    """
    if df.empty:
        logger.warning("extract_features: input DataFrame is empty — returning empty features")
        return pd.DataFrame()

    short_df = _extract_short_window_features(df)
    full_df  = _extract_full_session_features(df)

    # Combine both granularities into a single feature table.
    feature_df = pd.concat([short_df, full_df], ignore_index=True)

    logger.info(
        "extract_features: %d short-window rows + %d full-session rows = %d total",
        len(short_df), len(full_df), len(feature_df),
    )
    return feature_df
