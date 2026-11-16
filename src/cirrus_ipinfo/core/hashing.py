"""Canonical content hash and change attribution for enrichment versions.

``content_hash`` = sha256 of canonical JSON of ``{"v": <schema key>,
<layer>: {field: value}}``. The *schema key* is the part of
``enricher_version`` after ``+``, e.g. ``h1.c1``:

* ``h`` = ``HASH_SCHEMA_VERSION``: increase it whenever the meaning of a hashed
  field changes (parser fix, new field, normalisation change).
* ``c`` = the category rules version (``data/category-rules.json``).

When either changes, every affected IP gets one new version marked
``enricher``, so changes in our own interpretation stay distinguishable from
real data changes. The package version is deliberately *not* hashed. A release
that doesn't change output must not create a new version for every IP.
"""

from __future__ import annotations

import hashlib
import json

from .. import __version__
from .model import LAYERS, EnrichmentRecord

HASH_SCHEMA_VERSION = 3   # 2: added the category layer; 3: full geo (GeoLite2) + asinfo layer


def enricher_version(category_rules_version: int) -> str:
    return f"{__version__}+h{HASH_SCHEMA_VERSION}.c{category_rules_version}"


def schema_key(version: str) -> str:
    """``'0.1.0+h2.c1'`` → ``'h2.c1'`` (empty if no ``+``)."""
    _, sep, tail = version.partition("+")
    return tail if sep else ""


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def content_hash(rec: EnrichmentRecord) -> bytes:
    doc = {"v": schema_key(rec.enricher_version), **{layer: rec.layer_values(layer) for layer in LAYERS}}
    return hashlib.sha256(_canonical(doc)).digest()


def changed_layers(prev: EnrichmentRecord | None, new: EnrichmentRecord) -> tuple[str, ...]:
    """Layers that differ from ``prev``; empty tuple means "same version".

    ``('initial',)`` for the first version of an IP. ``'enricher'`` is added
    when the hash schema or category rules changed. If it's the *only* entry,
    nothing in the data changed and only our interpretation did.
    """
    if prev is None:
        return ("initial",)
    layers = [l for l in LAYERS if prev.layer_values(l) != new.layer_values(l)]
    if schema_key(prev.enricher_version) != schema_key(new.enricher_version):
        layers.append("enricher")
    return tuple(sorted(layers))
