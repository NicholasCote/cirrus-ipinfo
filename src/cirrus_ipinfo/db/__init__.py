"""Database access: connection settings and Alembic migrations."""

from __future__ import annotations

import os

OWNER_ROLE = "ipinfo_owner"


def database_url(env_var: str = "IPINFO_DATABASE_URL") -> str:
    """libpq URI from the environment (CNPG's ``<cluster>-app``-style ``uri`` key).

    Returned with the ``postgresql+psycopg`` driver prefix for SQLAlchemy.
    """
    url = os.environ.get(env_var)
    if not url:
        raise RuntimeError(f"{env_var} is not set")
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url
