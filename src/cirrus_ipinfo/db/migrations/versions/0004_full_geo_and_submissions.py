"""Full geo (GeoLite2: postal, time zone, lat/lon), IPinfo AS label, and the submission queue.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-16
"""

from cirrus_ipinfo.db.migrations.sqlfile import run_sql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql("0004_full_geo_and_submissions.sql")


def downgrade() -> None:
    raise NotImplementedError("forward-only: write a new revision instead")
