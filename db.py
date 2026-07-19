"""
db.py — SQLite Storage via SQLAlchemy ORM
==========================================
Responsibility: define the database schema, initialise the database, and
provide simple CRUD functions for sessions and results.

Two tables:
  sessions — one row per uploaded CSV file (upload audit trail)
  results  — one row per consolidated threat detection result

Usage:
    from db import init_db, save_session, save_results, get_session, get_results
    init_db()          # call once at app startup
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

# SQLite file lives in the project root.  The path can be overridden by passing
# a different URL to init_db().
_DEFAULT_DB_URL = "sqlite:///packetguard.db"

_engine = None
_SessionLocal = None


def init_db(db_url: str = _DEFAULT_DB_URL) -> None:
    """Initialise the database engine and create tables if they don't exist.

    Must be called once at application startup (before any other db function).

    Parameters
    ----------
    db_url : str
        SQLAlchemy-compatible database URL.  Defaults to a local SQLite file.
    """
    global _engine, _SessionLocal
    _engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},  # required for SQLite + Flask
    )
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)
    logger.info("init_db: database initialised at '%s'", db_url)


def _get_session() -> Session:
    """Return a new SQLAlchemy database session."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _SessionLocal()


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class UploadSession(Base):
    """Audit record for each uploaded capture file."""

    __tablename__ = "sessions"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    filename        = Column(String(255), nullable=False)
    uploaded_at     = Column(DateTime, nullable=False,
                             default=lambda: datetime.now(timezone.utc))
    packet_count    = Column(Integer, nullable=False, default=0)
    dropped_row_count = Column(Integer, nullable=False, default=0)

    # Relationship: one session → many results.
    results = relationship("DetectionResult", back_populates="session",
                           cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return (
            f"<UploadSession id={self.id} filename='{self.filename}' "
            f"packets={self.packet_count}>"
        )


class DetectionResult(Base):
    """One row per consolidated threat detection entry."""

    __tablename__ = "results"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    session_id   = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    threat_type  = Column(String(64), nullable=False)
    src_ip       = Column(String(45), nullable=True)   # 45 chars covers IPv6 too
    dst_ip       = Column(String(45), nullable=True)
    reason       = Column(Text, nullable=False)
    layer        = Column(String(64), nullable=False)
    window_start = Column(Float, nullable=True)
    window_end   = Column(Float, nullable=True)

    # Back-reference to session.
    session = relationship("UploadSession", back_populates="results")

    def __repr__(self) -> str:
        return (
            f"<DetectionResult id={self.id} threat='{self.threat_type}' "
            f"src='{self.src_ip}' dst='{self.dst_ip}'>"
        )


# ---------------------------------------------------------------------------
# CRUD functions
# ---------------------------------------------------------------------------

def save_session(filename: str, packet_count: int, dropped_row_count: int) -> int:
    """Insert a new session record and return its auto-assigned ID.

    Parameters
    ----------
    filename : str
        Original filename of the uploaded capture.
    packet_count : int
        Number of packets retained after cleaning.
    dropped_row_count : int
        Number of rows discarded during ingestion.

    Returns
    -------
    int
        The new session's primary key ID.
    """
    db = _get_session()
    try:
        session_row = UploadSession(
            filename=filename,
            packet_count=packet_count,
            dropped_row_count=dropped_row_count,
            uploaded_at=datetime.now(timezone.utc),
        )
        db.add(session_row)
        db.commit()
        db.refresh(session_row)
        session_id = session_row.id
        logger.info("save_session: created session id=%d for '%s'", session_id, filename)
        return session_id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def save_results(session_id: int, consolidated_flags: list[dict]) -> None:
    """Insert all consolidated threat flags for a given session.

    Parameters
    ----------
    session_id : int
        Primary key of the parent ``UploadSession`` row.
    consolidated_flags : list[dict]
        Output from ``result_consolidation.consolidate()``.
    """
    if not consolidated_flags:
        logger.info("save_results: no flags to save for session %d", session_id)
        return

    db = _get_session()
    try:
        for flag in consolidated_flags:
            row = DetectionResult(
                session_id=session_id,
                threat_type=flag.get("threat_type", "Unknown"),
                src_ip=flag.get("src_ip"),
                dst_ip=flag.get("dst_ip"),
                reason=flag.get("reason", ""),
                layer=flag.get("layer", ""),
                window_start=flag.get("window_start"),
                window_end=flag.get("window_end"),
            )
            db.add(row)
        db.commit()
        logger.info("save_results: saved %d results for session %d",
                    len(consolidated_flags), session_id)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_session(session_id: int) -> Optional[UploadSession]:
    """Retrieve one session by ID.

    Parameters
    ----------
    session_id : int

    Returns
    -------
    UploadSession or None
        Returns None if the session does not exist.
    """
    db = _get_session()
    try:
        return db.get(UploadSession, session_id)
    finally:
        db.close()


def get_results(session_id: int) -> list[DetectionResult]:
    """Retrieve all detection results for a given session, ordered by ID.

    Parameters
    ----------
    session_id : int

    Returns
    -------
    list[DetectionResult]
    """
    db = _get_session()
    try:
        return (
            db.query(DetectionResult)
            .filter(DetectionResult.session_id == session_id)
            .order_by(DetectionResult.id)
            .all()
        )
    finally:
        db.close()


def get_all_sessions() -> list[UploadSession]:
    """Return all sessions ordered by upload time (newest first).

    Used by the history/index page if we want to list past scans.
    """
    db = _get_session()
    try:
        return (
            db.query(UploadSession)
            .order_by(UploadSession.uploaded_at.desc())
            .all()
        )
    finally:
        db.close()
