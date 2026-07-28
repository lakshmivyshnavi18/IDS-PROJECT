"""
database/db.py
─────────────────────────────────────────────────────────────────────────────
Database initialization and session factory.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session as DBSession
from config import DB_PATH
from database.models import Base

# Ensure parent directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite + async
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    print(f"  ✓ Database initialized at: {DB_PATH}")


def get_db() -> DBSession:
    """
    Dependency injector for FastAPI routes.
    Yields a database session and ensures cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
