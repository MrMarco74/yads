"""
Guard against an ORM upgrade silently breaking every timestamp write.

The whole codebase stores naive UTC (`datetime.utcnow()`), and every
timestamp column in Postgres is `timestamp without time zone` to match.
SQLModel 0.0.40+ maps a bare `datetime` field to its own UTCDateTime type,
whose bind processor raises

    ValueError: Datetime values must have timezone information.

on any naive value. requirements.txt had `sqlmodel` unpinned, so the
2026-09-22 image rebuild pulled 0.0.45 and every API-key authenticated
request started 500ing on the `last_used_at` update -- the first write any
request happens to make. Every other timestamp write in the app was equally
broken; that one just failed first.

Asserting on the column's bind processor rather than a live insert keeps the
check independent of a database: it is the exact step that rejected the
value in production.
"""
from datetime import datetime

import pytest
from sqlalchemy.dialects import postgresql

from yads.models import APIKey, ModuleState, Target

TIMESTAMP_COLUMNS = [
    (APIKey, "last_used_at"),
    (APIKey, "created_at"),
    (ModuleState, "last_scanned_at"),
    (Target, "queued_at"),
]


@pytest.mark.parametrize("model, column_name", TIMESTAMP_COLUMNS)
def test_timestamp_columns_accept_naive_utc(model, column_name):
    """datetime.utcnow() must survive binding -- the codebase stores naive UTC."""
    column_type = model.__table__.columns[column_name].type
    dialect = postgresql.dialect()

    processor = column_type.bind_processor(dialect)
    value = datetime.utcnow()

    bound = processor(value) if processor else value

    assert bound is not None
