"""
result_consolidation.py — Module 5: Merge, Deduplicate & Report
================================================================
Responsibility: take the flag lists from the rule engine and the ML engine,
merge them into a single list, deduplicate overlapping detections, and sort for
readability.

Deduplication logic:
    If a rule-based flag and an ML flag share the same (src_ip, dst_ip) pair
    AND their time windows overlap (or both lack windows), they are merged into
    a single entry with layer = "rule-based + machine-learning".  The merged
    entry uses the rule-based reason (more specific) and appends a note that the
    ML engine independently confirmed the anomaly.

    Threat type priority when merging: the rule-based label is preferred because
    it is more specific (e.g. "SYN Flood") vs "Anomalous Flow".

Sort order:
    Primary: threat_type severity (SYN Flood > Port Scan > ARP > Anomalous Flow)
    Secondary: src_ip (alphabetical)
    This ordering surfaces the most critical threats at the top of the report.

Output contract (each dict in the returned list):
    threat_type  (str)
    src_ip       (str)
    dst_ip       (str | None)
    reason       (str)
    layer        (str)   — "rule-based", "machine-learning", or
                           "rule-based + machine-learning"
    window_start (float | None)
    window_end   (float | None)
"""

from __future__ import annotations

import logging
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering (lower index = higher severity)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Final[list[str]] = [
    "SYN Flood",
    "Port Scan (Fast)",
    "Port Scan (Slow)",
    "ARP Spoofing",
    "Anomalous Flow",
]


def _severity_key(flag: dict) -> tuple[int, str]:
    """Return a tuple (severity_rank, src_ip) for sorting.

    Unknown threat types are placed after all known types.
    """
    threat = flag.get("threat_type", "")
    try:
        rank = _SEVERITY_ORDER.index(threat)
    except ValueError:
        rank = len(_SEVERITY_ORDER)
    return rank, str(flag.get("src_ip", ""))


# ---------------------------------------------------------------------------
# Window-overlap check
# ---------------------------------------------------------------------------

def _windows_overlap(f1: dict, f2: dict) -> bool:
    """Return True if the two flags have overlapping (or absent) time windows.

    Two flags without any window information are considered to overlap
    (e.g. ARP Spoofing + ML anomaly on the same IP).
    """
    s1, e1 = f1.get("window_start"), f1.get("window_end")
    s2, e2 = f2.get("window_start"), f2.get("window_end")

    # If either flag has no window, treat as overlapping.
    if s1 is None or e1 is None or s2 is None or e2 is None:
        return True

    # Standard interval overlap: [s1, e1] overlaps [s2, e2] iff s1 <= e2 and s2 <= e1.
    return s1 <= e2 and s2 <= e1


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _merge_flags(rule_flags: list[dict], ml_flags: list[dict]) -> list[dict]:
    """Merge rule and ML flags, combining those that refer to the same flow/window.

    Algorithm:
    1. Start with all rule-based flags.
    2. For each ML flag, check if any rule flag matches on (src_ip, dst_ip) AND
       has an overlapping window.
    3. If yes → mark the matched rule flag as layer="rule-based + machine-learning"
       and append an ML-confirmation note to its reason.
    4. If no → add the ML flag as a standalone entry.

    Parameters
    ----------
    rule_flags, ml_flags : list[dict]
        Flags from the rule engine and ML engine respectively.

    Returns
    -------
    list[dict]
        Deduplicated combined list.
    """
    # Work on copies to avoid mutating caller's lists.
    merged: list[dict] = [dict(f) for f in rule_flags]
    matched_rule_indices: set[int] = set()

    for ml_flag in ml_flags:
        ml_src = ml_flag.get("src_ip")
        ml_dst = ml_flag.get("dst_ip")

        # Try to find a matching rule-based flag.
        match_idx = None
        for i, rule_flag in enumerate(merged):
            same_pair = (
                rule_flag.get("src_ip") == ml_src and
                rule_flag.get("dst_ip") == ml_dst
            )
            if same_pair and _windows_overlap(rule_flag, ml_flag):
                match_idx = i
                break

        if match_idx is not None:
            # Merge: upgrade layer label and append ML confirmation note.
            merged[match_idx]["layer"] = "rule-based + machine-learning"
            merged[match_idx]["reason"] += (
                f" [ML engine independently confirmed: {ml_flag['reason']}]"
            )
            matched_rule_indices.add(match_idx)
            logger.debug(
                "_merge_flags: merged ML flag into rule flag for %s → %s",
                ml_src, ml_dst,
            )
        else:
            # Standalone ML anomaly — no matching rule flag.
            merged.append(dict(ml_flag))
            logger.debug(
                "_merge_flags: standalone ML flag for %s → %s",
                ml_src, ml_dst,
            )

    return merged


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def consolidate(rule_flags: list[dict], ml_flags: list[dict]) -> list[dict]:
    """Merge, deduplicate, and sort all detection flags.

    Parameters
    ----------
    rule_flags : list[dict]
        Flags from ``rule_engine.run_rules()``.
    ml_flags : list[dict]
        Flags from ``ml_engine.run_isolation_forest()``.

    Returns
    -------
    list[dict]
        Deduplicated, sorted list of threat reports.  Each dict has:
        threat_type, src_ip, dst_ip, reason, layer, window_start, window_end.
    """
    if not rule_flags and not ml_flags:
        logger.info("consolidate: no flags from either layer — nothing to report")
        return []

    merged = _merge_flags(rule_flags, ml_flags)
    merged.sort(key=_severity_key)

    logger.info(
        "consolidate: %d rule flags + %d ML flags → %d consolidated results",
        len(rule_flags), len(ml_flags), len(merged),
    )
    return merged
