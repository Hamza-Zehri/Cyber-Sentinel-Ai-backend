"""
Pytest fixtures for Cyber Sentinel AI backend tests.
Uses an isolated in-memory SQLite database per test session so tests never
touch a real Postgres instance. UUID columns are transparently patched to a
CHAR(36)-backed type since SQLite has no native UUID type.
"""
import os
import uuid as uuid_mod

import pytest
import sqlalchemy as sa
from sqlalchemy import CHAR, TypeDecorator
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("DEFAULT_ADMIN_EMAIL", "admin@cybersentinel.ai")


class _SQLiteUUID(TypeDecorator):
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        return str(value) if value is not None else value

    def process_result_value(self, value, dialect):
        return uuid_mod.UUID(value) if value is not None else value


import sqlalchemy.dialects.postgresql as _pgd
_pgd.UUID = lambda as_uuid=True: _SQLiteUUID()  # noqa: E731


@pytest.fixture()
def client():
    """Fresh app + fresh in-memory DB for every test function."""
    from app.database import Base
    import app.database as dbmod

    test_engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    dbmod.engine = test_engine
    dbmod.SessionLocal.configure(bind=test_engine)

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db_session():
    from app.database import SessionLocal
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
