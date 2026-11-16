"""Provenance types shared by every layer (kept dependency-free to avoid import cycles)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class SourceRef:
    """A dataset snapshot that contributed to a result."""

    source: str
    snapshot_date: date | None
    snapshot_id: int | None = None
    attribution: str | None = None
