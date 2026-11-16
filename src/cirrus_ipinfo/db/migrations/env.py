"""Alembic environment. Migrations are plain SQL files run as ``ipinfo_owner``."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool, text

from cirrus_ipinfo.db import OWNER_ROLE, database_url

url = context.config.get_main_option("sqlalchemy.url") or database_url()


def run() -> None:
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as conn:
        # The login role may be ipinfo_owner itself or a member of it (e.g. an
        # OpenBao dynamic role); either way objects must end up owned by it.
        if conn.execute(text("SELECT current_user")).scalar() != OWNER_ROLE:
            conn.execute(text(f"SET ROLE {OWNER_ROLE}"))
        conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS ipinfo AUTHORIZATION {OWNER_ROLE}"))
        conn.commit()
        context.configure(connection=conn, version_table_schema="ipinfo", transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("offline (--sql) mode is not supported; the SQL files are in migrations/versions/")
run()
