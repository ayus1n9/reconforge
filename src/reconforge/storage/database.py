"""Database connection management and SQLite configuration."""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("reconforge.storage.db")

Base = declarative_base()


class DatabaseManager:
    """Manages SQLite database connections with WAL mode and strict foreign key integrity."""

    def __init__(self, db_url: str | None = None):
        self.db_url = db_url or os.getenv("RECONFORGE_DB_URL", "sqlite:///reconforge.db")
        self.is_sqlite = self.db_url.startswith("sqlite")

        engine_kwargs: dict[str, Any] = {
            "echo": False,
            "future": True,
        }
        if self.is_sqlite:
            engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30.0}
            if ":memory:" in self.db_url:
                engine_kwargs["poolclass"] = StaticPool

        self.engine = create_engine(self.db_url, **engine_kwargs)

        if self.is_sqlite:
            self._configure_sqlite_pragmas()

        self.session_factory = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            autoflush=False,
            future=True,
        )

    def _configure_sqlite_pragmas(self) -> None:
        """Enforce WAL mode and foreign key integrity on every SQLite connection."""

        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON;")
                # WAL mode cannot be used on in-memory SQLite databases
                if ":memory:" not in self.db_url:
                    cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute("PRAGMA busy_timeout=5000;")
            finally:
                cursor.close()

    def init_db(self) -> None:
        """Create all registered database tables."""
        Base.metadata.create_all(bind=self.engine)
        logger.debug("Database initialized with URL: %s", self.db_url)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Context manager providing an atomic transactional database session."""
        session: Session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
