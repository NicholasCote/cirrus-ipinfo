"""Observation ingress controller (traefik, ingress-nginx).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-13
"""

from cirrus_ipinfo.db.migrations.sqlfile import run_sql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql("0003_observation_ingress.sql")


def downgrade() -> None:
    raise NotImplementedError("forward-only: write a new revision instead")
