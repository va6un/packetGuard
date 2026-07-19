"""
app.py — Flask Application Entry Point
=======================================
Responsibility: handle HTTP requests, orchestrate the full detection pipeline,
persist results, and render Jinja2 templates.

Routes:
  GET  /              → upload form
  POST /upload        → run pipeline, redirect to results
  GET  /results/<id>  → render results page from SQLite

Pipeline order (per spec):
  ingest → extract_features → run_rules + run_isolation_forest (both) → consolidate
  → save to DB → redirect

Error handling:
  Custom ingestion exceptions (SchemaValidationError, EmptyFileError) are caught
  and shown as flash messages.  Unexpected errors also caught and flash a generic
  message so the user NEVER sees a raw stack trace.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import db
from feature_extraction import extract_features
from ingestion import EmptyFileError, IngestionError, SchemaValidationError, ingest
from ml_engine import run_isolation_forest
from result_consolidation import consolidate
from rule_engine import run_rules

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "packetguard-dev-secret-key")

# Uploaded files are stored in a temporary directory relative to the project root.
UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"csv"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the file upload page."""
    sessions = db.get_all_sessions()
    return render_template("upload.html", sessions=sessions)


@app.route("/upload", methods=["POST"])
def upload():
    """Accept a CSV upload, run the full detection pipeline, persist, redirect."""
    if "capture_file" not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for("index"))

    file = request.files["capture_file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    if not _allowed_file(file.filename):
        flash("Only CSV files are accepted.", "error")
        return redirect(url_for("index"))

    # Save the uploaded file.
    safe_name = secure_filename(file.filename)
    save_path = UPLOAD_FOLDER / safe_name
    file.save(str(save_path))
    logger.info("upload: saved '%s' to '%s'", safe_name, save_path)

    # --- Run the pipeline ---
    try:
        # Module 1: Ingest
        packet_df, meta = ingest(str(save_path))
        logger.info("upload: ingestion complete — %d packets", meta["packet_count"])

        # Module 2: Feature extraction
        feature_df = extract_features(packet_df)
        logger.info("upload: feature extraction complete — %d feature rows", len(feature_df))

        # Module 3: Rule-based detection
        rule_flags = run_rules(feature_df, packet_df)
        logger.info("upload: rule engine complete — %d flags", len(rule_flags))

        # Module 4: ML-based detection
        ml_flags = run_isolation_forest(feature_df)
        logger.info("upload: ML engine complete — %d flags", len(ml_flags))

        # Module 5: Consolidate
        consolidated = consolidate(rule_flags, ml_flags)
        logger.info("upload: consolidation complete — %d results", len(consolidated))

        # Persist to DB
        session_id = db.save_session(
            filename=safe_name,
            packet_count=meta["packet_count"],
            dropped_row_count=meta["dropped_count"],
        )
        db.save_results(session_id, consolidated)

        if consolidated:
            flash(
                f"Analysis complete: {len(consolidated)} threat(s) detected.",
                "success",
            )
        else:
            flash("Analysis complete: no threats detected in this capture.", "info")

        return redirect(url_for("results", session_id=session_id))

    except SchemaValidationError as exc:
        flash(f"Schema error: {exc}", "error")
        logger.warning("upload: schema validation error — %s", exc)
    except EmptyFileError as exc:
        flash(f"File error: {exc}", "error")
        logger.warning("upload: empty file error — %s", exc)
    except IngestionError as exc:
        flash(f"Ingestion error: {exc}", "error")
        logger.warning("upload: ingestion error — %s", exc)
    except Exception as exc:
        flash(
            "An unexpected error occurred during analysis. "
            "Please check that the file follows the required tshark format.",
            "error",
        )
        logger.exception("upload: unexpected error — %s", exc)
    finally:
        # Clean up the uploaded file regardless of success or failure.
        try:
            save_path.unlink(missing_ok=True)
        except Exception:
            pass

    return redirect(url_for("index"))


@app.route("/results/<int:session_id>")
def results(session_id: int):
    """Render the consolidated threat report for a given session."""
    session_row = db.get_session(session_id)
    if session_row is None:
        flash(f"Session {session_id} not found.", "error")
        return redirect(url_for("index"))

    result_rows = db.get_results(session_id)

    # Build summary statistics for the template.
    layer_breakdown: dict[str, int] = {}
    for r in result_rows:
        layer_breakdown[r.layer] = layer_breakdown.get(r.layer, 0) + 1

    return render_template(
        "results.html",
        session=session_row,
        results=result_rows,
        layer_breakdown=layer_breakdown,
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    db.init_db()
    app.run(debug=True)
