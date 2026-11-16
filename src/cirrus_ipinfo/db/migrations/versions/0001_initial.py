"""Initial schema: provenance, tenants, networks, enrichment versions, observations.

Revision ID: 0001
Revises:
Create Date: 2026-11-13
"""

from cirrus_ipinfo.db.migrations.sqlfile import run_sql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql("0001_initial.sql")


def downgrade() -> None:
    raise NotImplementedError("forward-only: write a new revision instead")
