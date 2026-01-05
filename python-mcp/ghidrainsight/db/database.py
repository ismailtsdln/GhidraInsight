"""Database connection and session management."""

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from ..config import settings
from .models import Base


def get_database_url() -> str:
    """Get database URL from config or default to SQLite for development."""
    if settings.database.url:
        return settings.database.url
    return "sqlite:///./ghidrainsight.db"


def create_engine_instance():
    """Create SQLAlchemy engine."""
    database_url = get_database_url()

    if database_url.startswith("sqlite"):
        # SQLite specific configuration
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=settings.database.echo,
        )
    else:
        # PostgreSQL configuration
        return create_engine(
            database_url,
            pool_size=settings.database.pool_size,
            max_overflow=settings.database.max_overflow,
            echo=settings.database.echo,
        )


# Global engine instance
engine = create_engine_instance()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for getting database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables."""
    Base.metadata.drop_all(bind=engine)
