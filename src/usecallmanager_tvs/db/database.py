"""Database engine and session management for TVS."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from usecallmanager_tvs.db.models import Base

_engine = None
_session_factory = None


def get_engine(database_url: str):
    """Get or create the database engine."""
    global _engine
    if _engine is None:
        # Handle SQLite URL for file path
        if database_url.startswith("sqlite:///"):
            connect_args = {"check_same_thread": False}
        else:
            connect_args = {}

        _engine = create_engine(
            database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
    return _engine


def get_session(database_url: str) -> scoped_session[Session]:
    """Get a thread-safe scoped session."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine(database_url)
        session_factory = sessionmaker(bind=engine)
        _session_factory = scoped_session(session_factory)
    return _session_factory


def init_db(database_url: str):
    """Initialize the database, creating tables if they don't exist."""
    engine = get_engine(database_url)
    Base.metadata.create_all(engine)
