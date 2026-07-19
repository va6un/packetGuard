"""
ml_engine.py — Module 4: Isolation Forest Anomaly Detection
============================================================
Responsibility: fit an Isolation Forest on the per-capture flow features and
return a flag dict for every flow scored as anomalous.

Design decisions:
- The model is fit FRESH on every uploaded capture (unsupervised, per-capture).
  No pretrained model is persisted between sessions.  This is intentional and
  matches the project's design (Isolation Forest detects statistical outliers
  within the capture itself, not against a historical baseline).
- sklearn is only imported inside this module; no other module imports it.
- Explainability: for each flagged flow, the top 1–2 features with the largest
  absolute z-score are identified and written into the ``reason`` string.
  This avoids the vague "anomaly detected" anti-pattern.

Flag dict schema matches rule_engine.py:
    threat_type, src_ip, dst_ip, reason, layer, window_start, window_end
"""

from __future__ import annotations

import logging
from typing import Final

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LAYER: Final[str] = "machine-learning"

# Numeric feature columns used as input to the model.
_FEATURE_COLS: Final[list[str]] = [
    "packet_rate",
    "byte_volume",
    "unique_dst_ports",
    "duration",
    "syn_ack_ratio",
    "tcp_frac",
    "udp_frac",
    "icmp_frac",
    "other_frac",
]

# Number of top features to mention in the reason string.
_TOP_N_FEATURES: Final[int] = 2


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_reason(row_idx: int, z_scores: np.ndarray, feature_names: list[str]) -> str:
    """Build a plain-English reason string from the top z-scored features.

    Parameters
    ----------
    row_idx : int
        Index into z_scores for the flagged row.
    z_scores : np.ndarray
        2D array of z-scores, shape (n_samples, n_features).
    feature_names : list[str]
        Column names corresponding to z_score columns.

    Returns
    -------
    str
        Human-readable explanation, e.g.
        "byte_volume is 6.2 standard deviations above the capture average;
         packet_rate is 4.1 standard deviations above the capture average"
    """
    row_z = z_scores[row_idx]
    abs_z = np.abs(row_z)

    # Get indices of top N features by absolute z-score.
    top_indices = np.argsort(abs_z)[::-1][:_TOP_N_FEATURES]

    parts = []
    for idx in top_indices:
        feat_name  = feature_names[idx]
        z_val      = row_z[idx]
        direction  = "above" if z_val > 0 else "below"
        parts.append(
            f"{feat_name} is {abs(z_val):.1f} standard deviations {direction} "
            f"the capture average"
        )

    return "; ".join(parts) + "." if parts else "Anomalous flow detected."


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def run_isolation_forest(feature_df: pd.DataFrame) -> list[dict]:
    """Fit Isolation Forest on the feature table and flag anomalous flows.

    Parameters
    ----------
    feature_df : pd.DataFrame
        Flow feature table from ``feature_extraction.extract_features()``.
        Must contain the columns listed in ``_FEATURE_COLS``.

    Returns
    -------
    list[dict]
        Flag dicts for each anomalous flow.  The list is empty if the feature
        table has fewer than 2 rows (not enough data for meaningful anomaly
        detection) or if no anomalies are found.
    """
    # Deferred sklearn import — keeps this module self-contained.
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    flags: list[dict] = []

    if feature_df.empty or len(feature_df) < 2:
        logger.warning(
            "run_isolation_forest: not enough rows (%d) for anomaly detection",
            len(feature_df),
        )
        return flags

    # --- Select and prepare numeric features ---
    # Only use columns that are actually present (guards against schema drift).
    available_cols = [c for c in _FEATURE_COLS if c in feature_df.columns]
    if not available_cols:
        logger.error("run_isolation_forest: no feature columns available")
        return flags

    X_raw = feature_df[available_cols].fillna(0).to_numpy(dtype=float)

    # --- Standardise ---
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    # Store z-scores (same as X_scaled since StandardScaler gives z-scores).
    z_scores = X_scaled

    # --- Fit Isolation Forest ---
    # contamination='auto' lets sklearn decide the anomaly fraction
    # (equivalent to 0.1 in most sklearn versions but avoids a hard-coded guess).
    iso_forest = IsolationForest(contamination="auto", random_state=42)
    predictions = iso_forest.fit_predict(X_scaled)  # -1 = anomaly, +1 = normal

    # --- Collect flagged rows ---
    anomaly_indices = np.where(predictions == -1)[0]
    logger.info(
        "run_isolation_forest: %d anomalies detected out of %d flows",
        len(anomaly_indices), len(feature_df),
    )

    for idx in anomaly_indices:
        row = feature_df.iloc[idx]
        reason = _build_reason(int(idx), z_scores, available_cols)

        flags.append({
            "threat_type":  "Anomalous Flow",
            "src_ip":       row["src_ip"],
            "dst_ip":       row["dst_ip"],
            "reason":       reason,
            "layer":        _LAYER,
            "window_start": float(row["window_start"]) if pd.notna(row.get("window_start")) else None,
            "window_end":   float(row["window_end"]) if pd.notna(row.get("window_end")) else None,
        })
        logger.debug(
            "run_isolation_forest: anomaly — %s → %s | %s",
            row["src_ip"], row["dst_ip"], reason,
        )

    return flags
