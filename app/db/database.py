"""
Database setup using SQLAlchemy (async) with SQLite via aiosqlite.

Usage
-----
Call ``init_db()`` once at startup to create all tables, then use
``get_db()`` as a FastAPI dependency to obtain a session.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# Async engine — SQLite file lives next to the app unless overridden
engine = create_async_engine(
    settings.database_url,
    # echo=True shows generated SQL — helpful for debugging, keep False in prod
    echo=settings.debug,
    connect_args={"check_same_thread": False},
)

# Factory that produces AsyncSession objects
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


async def init_db() -> None:
    """Create all database tables (idempotent — safe to call on every startup)."""
    async with engine.begin() as conn:
        # Import models so their metadata is registered with Base before we
        # call create_all.
        from app.models import scan, user  # noqa: F401

        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """
    FastAPI dependency that yields a database session.

    The session is automatically closed when the request finishes.
    """
    async with AsyncSessionLocal() as session:
        yield session
