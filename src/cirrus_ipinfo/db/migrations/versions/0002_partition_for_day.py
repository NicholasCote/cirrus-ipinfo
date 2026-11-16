"""Observation partition for any day (backfills).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-13
"""

from cirrus_ipinfo.db.migrations.sqlfile import run_sql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql("0002_partition_for_day.sql")


def downgrade() -> None:
    raise NotImplementedError("forward-only: write a new revision instead")
