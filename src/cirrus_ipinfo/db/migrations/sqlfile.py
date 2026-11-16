"""Run a revision's ``.sql`` file through Alembic's connection."""

from __future__ import annotations

from pathlib import Path

from alembic import op


def run_sql(filename: str) -> None:
    sql = (Path(__file__).parent / "versions" / filename).read_text()
    # Straight to the psycopg connection with params=None: psycopg then runs it
    # as one multi-statement script and leaves the %-placeholders inside the
    # plpgsql format() calls alone (SQLAlchemy would pass () and trip on them).
    op.get_bind().connection.driver_connection.execute(sql)
