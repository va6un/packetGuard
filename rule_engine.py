"""
rule_engine.py — Module 3: Rule-Based Detection Engine
=======================================================
Responsibility: apply hand-crafted detection rules to the flow feature table
(and, in one case, the raw packet DataFrame) and return a list of flag dicts.

Each rule is its own function for testability and clarity.
``run_rules()`` is the single public entrypoint that orchestrates all rules.

Flag dict schema (every rule returns dicts with these keys):
    threat_type  (str)   — human-readable threat category label
    src_ip       (str)   — source IP of the suspicious flow (or IP under scrutiny)
    dst_ip       (str | None) — destination IP, None for ARP-based flags
    reason       (str)   — plain-English sentence with actual triggering values
    layer        (str)   — always "rule-based" for this module
    window_start (float | None)
    window_end   (float | None)
"""

from __future__ import annotations

import logging
from typing import Final

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants (named for viva explainability)
# ---------------------------------------------------------------------------

# SYN Flood: minimum syn_ack_ratio to trigger.
SYN_FLOOD_RATIO_THRESHOLD: Final[float] = 5.0

# SYN Flood: minimum SYN count to avoid flagging tiny samples.
SYN_FLOOD_MIN_SYN_COUNT: Final[int] = 20

# Fast Port Scan: unique destination ports within one 10-second window.
FAST_SCAN_PORT_THRESHOLD: Final[int] = 15

# Slow Port Scan: unique destination ports across the full capture session.
SLOW_SCAN_PORT_THRESHOLD: Final[int] = 20

# Layer label.
_LAYER: Final[str] = "rule-based"

# Feature extraction window type labels (imported here as string constants to
# avoid a circular import from feature_extraction).
_WINDOW_SHORT: Final[str] = "short"
_WINDOW_FULL:  Final[str] = "full_session"


# ---------------------------------------------------------------------------
# Rule 1 — SYN Flood
# ---------------------------------------------------------------------------

def detect_syn_flood(feature_df: pd.DataFrame) -> list[dict]:
    """Detect SYN flood patterns in short-window flow features.

    A flow is flagged when, within a 10-second window:
    - syn_ack_ratio > SYN_FLOOD_RATIO_THRESHOLD (5.0)
    - syn_count >= SYN_FLOOD_MIN_SYN_COUNT (20)

    The minimum SYN count guard prevents flagging on tiny single-packet flows
    that happen to have a high ratio purely by coincidence.

    Parameters
    ----------
    feature_df : pd.DataFrame
        Feature table from ``feature_extraction.extract_features()``.

    Returns
    -------
    list[dict]
        List of flag dicts (possibly empty).
    """
    flags: list[dict] = []

    if feature_df.empty or "window_type" not in feature_df.columns:
        return flags

    short = feature_df[feature_df["window_type"] == _WINDOW_SHORT]
    if short.empty:
        return flags

    # Vectorized filter — no row-by-row loop.
    mask = (
        (short["syn_ack_ratio"] > SYN_FLOOD_RATIO_THRESHOLD) &
        (short["syn_count"] >= SYN_FLOOD_MIN_SYN_COUNT)
    )
    suspicious = short[mask]

    for _, row in suspicious.iterrows():
        reason = (
            f"SYN/ACK ratio of {row['syn_ack_ratio']:.1f} "
            f"({int(row['syn_count'])} SYN vs {int(row['ack_count'])} ACK) "
            f"in a {int(row['window_end'] - row['window_start'])}s window."
        )
        flags.append({
            "threat_type":  "SYN Flood",
            "src_ip":       row["src_ip"],
            "dst_ip":       row["dst_ip"],
            "reason":       reason,
            "layer":        _LAYER,
            "window_start": float(row["window_start"]),
            "window_end":   float(row["window_end"]),
        })
        logger.info("detect_syn_flood: flagged %s → %s", row["src_ip"], row["dst_ip"])

    return flags


# ---------------------------------------------------------------------------
# Rule 2 — Fast Port Scan (short window)
# ---------------------------------------------------------------------------

def detect_fast_port_scan(feature_df: pd.DataFrame) -> list[dict]:
    """Detect fast port scans: many unique destination ports within 10 seconds.

    Threshold: unique_dst_ports >= FAST_SCAN_PORT_THRESHOLD (15).

    Parameters
    ----------
    feature_df : pd.DataFrame
        Feature table from ``feature_extraction.extract_features()``.

    Returns
    -------
    list[dict]
        List of flag dicts.
    """
    flags: list[dict] = []

    if feature_df.empty or "window_type" not in feature_df.columns:
        return flags

    short = feature_df[feature_df["window_type"] == _WINDOW_SHORT]
    if short.empty:
        return flags

    mask = short["unique_dst_ports"] >= FAST_SCAN_PORT_THRESHOLD
    suspicious = short[mask]

    for _, row in suspicious.iterrows():
        reason = (
            f"Contacted {int(row['unique_dst_ports'])} unique destination ports "
            f"within a {int(row['window_end'] - row['window_start'])}s window "
            f"(threshold: {FAST_SCAN_PORT_THRESHOLD})."
        )
        flags.append({
            "threat_type":  "Port Scan (Fast)",
            "src_ip":       row["src_ip"],
            "dst_ip":       row["dst_ip"],
            "reason":       reason,
            "layer":        _LAYER,
            "window_start": float(row["window_start"]),
            "window_end":   float(row["window_end"]),
        })
        logger.info("detect_fast_port_scan: flagged %s → %s", row["src_ip"], row["dst_ip"])

    return flags


# ---------------------------------------------------------------------------
# Rule 3 — Slow Port Scan (full session)
# ---------------------------------------------------------------------------

def detect_slow_port_scan(
    feature_df: pd.DataFrame,
    fast_scan_flags: list[dict],
) -> list[dict]:
    """Detect slow port scans across the entire capture duration.

    Threshold: unique_dst_ports >= SLOW_SCAN_PORT_THRESHOLD (20) in the
    full-session window.

    Deduplication: if a fast-scan flag already covers the same (src_ip, dst_ip)
    pair, do NOT emit a slow-scan flag for it — the behavior is already captured
    at higher resolution by Rule 2.

    Parameters
    ----------
    feature_df : pd.DataFrame
        Feature table from ``feature_extraction.extract_features()``.
    fast_scan_flags : list[dict]
        Flags already raised by ``detect_fast_port_scan()``.

    Returns
    -------
    list[dict]
        List of flag dicts (slow-only; no overlap with fast-scan results).
    """
    flags: list[dict] = []

    if feature_df.empty or "window_type" not in feature_df.columns:
        return flags

    # Build a set of (src_ip, dst_ip) pairs already caught by the fast scan.
    already_flagged = {
        (f["src_ip"], f["dst_ip"])
        for f in fast_scan_flags
    }

    full = feature_df[feature_df["window_type"] == _WINDOW_FULL]
    if full.empty:
        return flags

    mask = full["unique_dst_ports"] >= SLOW_SCAN_PORT_THRESHOLD
    suspicious = full[mask]

    for _, row in suspicious.iterrows():
        pair = (row["src_ip"], row["dst_ip"])
        if pair in already_flagged:
            # Behavior already captured by the fast-scan rule — skip to avoid
            # showing the same underlying attack twice in the report.
            logger.debug(
                "detect_slow_port_scan: skipping %s → %s (already caught by fast-scan)",
                row["src_ip"], row["dst_ip"],
            )
            continue

        reason = (
            f"Contacted {int(row['unique_dst_ports'])} unique destination ports "
            f"over the full capture duration "
            f"(threshold: {SLOW_SCAN_PORT_THRESHOLD}). "
            f"Low packet rate ({row['packet_rate']:.2f} pkt/s) suggests a slow scan."
        )
        flags.append({
            "threat_type":  "Port Scan (Slow)",
            "src_ip":       row["src_ip"],
            "dst_ip":       row["dst_ip"],
            "reason":       reason,
            "layer":        _LAYER,
            "window_start": float(row["window_start"]),
            "window_end":   float(row["window_end"]),
        })
        logger.info("detect_slow_port_scan: flagged %s → %s", row["src_ip"], row["dst_ip"])

    return flags


# ---------------------------------------------------------------------------
# Rule 4 — ARP Spoofing
# ---------------------------------------------------------------------------

def detect_arp_spoofing(packet_df: pd.DataFrame) -> list[dict]:
    """Detect potential ARP spoofing by IP-to-MAC consistency checks.

    Method: group by src_ip and count distinct eth.src (MAC) addresses.
    If a single IP is seen with 2 or more distinct MAC addresses across the
    capture, that is a strong indicator of ARP spoofing (one legitimate host,
    one attacker claiming the same IP).

    Note: This rule operates directly on the packet DataFrame, not the flow
    feature table, because MAC-to-IP mapping is a per-packet property.

    Parameters
    ----------
    packet_df : pd.DataFrame
        Clean packet DataFrame from ``ingestion.ingest()``.

    Returns
    -------
    list[dict]
        List of flag dicts (one per suspicious IP).
    """
    flags: list[dict] = []

    if packet_df.empty or "src_ip" not in packet_df.columns or "eth_src" not in packet_df.columns:
        return flags

    # Only inspect rows where both src_ip and eth_src are present.
    relevant = packet_df[packet_df["src_ip"].notna() & packet_df["eth_src"].notna()]
    if relevant.empty:
        return flags

    # Count distinct MAC addresses per source IP.
    mac_counts = (
        relevant.groupby("src_ip")["eth_src"]
        .nunique()
    )

    # Flag IPs with more than one MAC.
    suspicious_ips = mac_counts[mac_counts > 1]

    for src_ip, mac_count in suspicious_ips.items():
        # Collect the actual MACs seen for this IP (for the reason string).
        macs_seen = sorted(
            relevant.loc[relevant["src_ip"] == src_ip, "eth_src"].unique()
        )
        reason = (
            f"IP {src_ip} was observed with {mac_count} different MAC addresses: "
            f"{', '.join(macs_seen)}. "
            f"This is consistent with ARP spoofing or IP address conflict."
        )
        flags.append({
            "threat_type":  "ARP Spoofing",
            "src_ip":       src_ip,
            "dst_ip":       None,
            "reason":       reason,
            "layer":        _LAYER,
            "window_start": None,
            "window_end":   None,
        })
        logger.info("detect_arp_spoofing: flagged IP %s (%d MACs)", src_ip, mac_count)

    return flags


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def run_rules(feature_df: pd.DataFrame, packet_df: pd.DataFrame) -> list[dict]:
    """Run all four detection rules and return the combined list of flags.

    Execution order matters:
    1. SYN Flood
    2. Fast Port Scan
    3. Slow Port Scan (uses fast-scan results to suppress duplicates)
    4. ARP Spoofing

    Parameters
    ----------
    feature_df : pd.DataFrame
        Flow feature table from ``feature_extraction.extract_features()``.
    packet_df : pd.DataFrame
        Raw (cleaned) packet DataFrame from ``ingestion.ingest()``.

    Returns
    -------
    list[dict]
        All rule-based flags, concatenated (possibly empty).
    """
    syn_flood_flags   = detect_syn_flood(feature_df)
    fast_scan_flags   = detect_fast_port_scan(feature_df)
    slow_scan_flags   = detect_slow_port_scan(feature_df, fast_scan_flags)
    arp_spoof_flags   = detect_arp_spoofing(packet_df)

    all_flags = syn_flood_flags + fast_scan_flags + slow_scan_flags + arp_spoof_flags

    logger.info(
        "run_rules: %d total flags "
        "(SYN flood: %d, fast scan: %d, slow scan: %d, ARP: %d)",
        len(all_flags),
        len(syn_flood_flags), len(fast_scan_flags),
        len(slow_scan_flags), len(arp_spoof_flags),
    )
    return all_flags
