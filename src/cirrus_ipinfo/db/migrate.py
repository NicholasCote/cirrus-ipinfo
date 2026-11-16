"""Programmatic Alembic entry point (``cirrus-ipinfo migrate``); no alembic.ini needed."""

from __future__ import annotations

from alembic import command
from alembic.config import Config

from . import database_url


def config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "cirrus_ipinfo.db:migrations")
    cfg.set_main_option("sqlalchemy.url", (url or database_url()).replace("%", "%%"))
    return cfg


def upgrade(revision: str = "head", url: str | None = None) -> None:
    command.upgrade(config(url), revision)


def current(url: str | None = None) -> None:
    command.current(config(url), verbose=True)


def wait_for_database(seconds: int, url: str | None = None) -> None:
    import time

    import psycopg

    dsn = (url or database_url()).replace("postgresql+psycopg://", "postgresql://", 1)
    deadline = time.monotonic() + seconds
    while True:
        try:
            psycopg.connect(dsn, connect_timeout=5).close()
            return
        except psycopg.OperationalError as exc:
            if time.monotonic() > deadline:
                raise
            print(f"database not ready yet ({str(exc).strip()[:120]}); retrying", flush=True)
            time.sleep(5)
