"""Three-level categorisation: category → subcategory → organisation.

* ``category`` / ``subcategory``: broad buckets for research reporting
  (e.g. ``education_research`` / ``university``).
* ``org_domain``: the registrable domain of the PTR name (``colorado.edu``,
  ``ox.ac.uk``), computed with the ICANN section of the Public Suffix List.
  The private section is ignored on purpose: it would turn
  ``ec2-….compute-1.amazonaws.com`` into thousands of distinct "organisations".
* ``org_name``: display name from the registry (network org), falling back to
  the AS name.
* ``category_basis``: which evidence decided the category, so every label
  can be explained.
* ``legacy_category``: an approximation of the existing team report (PTR TLD
  buckets such as COM/NET/UNIV), for side-by-side comparison.

PTR names are set by whoever controls the reverse zone, so a name that
doesn't forward-confirm (FCrDNS) is weaker evidence. Confirmed names are used
early in the precedence and unconfirmed names only as a last resort. The
precedence order is documented in ``data/category-rules.json``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from importlib import resources

from .addr import normalize
from .model import EnrichmentRecord


# ----------------------------------------------------------- public suffixes
def _to_ascii(rule: str) -> str | None:
    """Punycode each label of a PSL rule, keeping the ``!``/``*`` markers.

    PTR names arrive in ASCII (punycode) form, so the rules must too.
    """
    if rule.isascii():
        return rule
    prefix = "!" if rule.startswith("!") else ""
    out = []
    for label in rule.lstrip("!").split("."):
        if label == "*" or label.isascii():
            out.append(label)
            continue
        try:
            out.append(label.encode("idna").decode())
        except UnicodeError:
            return None
    return prefix + ".".join(out)


class PublicSuffixList:
    def __init__(self, text: str):
        self.normal: set[str] = set()
        self.wildcard: set[str] = set()   # stored without the leading "*."
        self.exception: set[str] = set()  # stored without the leading "!"
        self.version: str | None = None
        in_icann = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("// VERSION:"):
                self.version = line.split(":", 1)[1].strip()
            if "===BEGIN ICANN DOMAINS===" in line:
                in_icann = True
                continue
            if "===END ICANN DOMAINS===" in line:
                break
            if not in_icann or not line or line.startswith("//"):
                continue
            rule = _to_ascii(line.split()[0].lower())
            if rule is None:
                continue
            if rule.startswith("!"):
                self.exception.add(rule[1:])
            elif rule.startswith("*."):
                self.wildcard.add(rule[2:])
            else:
                self.normal.add(rule)

    @classmethod
    def default(cls) -> "PublicSuffixList":
        return cls((resources.files("cirrus_ipinfo") / "data" / "public_suffix_list.dat").read_text())

    def suffix_len(self, labels: list[str]) -> int:
        """Number of trailing labels forming the public suffix."""
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exception:
                return len(labels) - i - 1
            if cand in self.normal or ".".join(labels[i + 1:]) in self.wildcard and i + 1 < len(labels):
                return len(labels) - i
        return 1  # default rule "*": the TLD

    def registrable_domain(self, host: str | None) -> str | None:
        if not host:
            return None
        host = host.strip().rstrip(".").lower()
        labels = [l for l in host.split(".") if l]
        if len(labels) < 2:
            return None
        n = self.suffix_len(labels)
        if n >= len(labels):
            return None
        return ".".join(labels[-(n + 1):])


# ----------------------------------------------------------------- rules
def _suffix_matches(pattern: list[str], labels: list[str]) -> bool:
    if len(labels) <= len(pattern):   # need at least one label in front of the suffix
        return False
    tail = labels[-len(pattern):]
    return all(p == "*" or p == l for p, l in zip(pattern, tail, strict=True))


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


@dataclass(frozen=True)
class CategoryResult:
    category: str
    subcategory: str | None
    org_domain: str | None
    org_name: str | None
    basis: str
    legacy: str


class Categorizer:
    def __init__(self, rules: dict, psl: PublicSuffixList, asn_types: dict[int, str] | None = None):
        self.version: int = int(rules["version"])
        self.psl = psl
        self.asn_types = asn_types or {}
        internal = rules.get("internal", {})
        self._int_sub = internal.get("subcategory", "ncar_ucar")
        self._int_domains = {d.lower() for d in internal.get("domains", [])}
        self._int_asns = {int(a) for a in internal.get("asns", [])}
        self._int_nets = [ipaddress.ip_network(c) for c in internal.get("cidrs", [])]
        self._node_sub = internal.get("node_subcategory", "k8s_node")
        self._node_ptr = re.compile(internal["node_ptr_regex"], re.I) if internal.get("node_ptr_regex") else None
        self._node_nets = [ipaddress.ip_network(c) for c in internal.get("node_cidrs", [])]
        self._domain_over = {d.lower(): tuple(v) for d, v in rules.get("domain_overrides", {}).items()}
        self._asn_over = {int(a): tuple(v) for a, v in rules.get("asn_overrides", {}).items()}
        self._suffix_rules = [(p.lower().split("."), c, s) for p, c, s in rules.get("ptr_suffix_rules", [])]
        self._pdb = {k: tuple(v) for k, v in rules.get("peeringdb_types", {}).items()}
        self._org_kw = [(re.compile(rx, re.I), cat, sub) for rx, cat, sub in rules.get("org_keyword_rules", [])]
        self._ptr_labels = [({t.lower() for t in tokens}, cat, sub) for tokens, cat, sub in rules.get("ptr_label_rules", [])]
        self._company = [re.compile(rules[k], re.I) for k in ("company_suffix", "company_prefix") if rules.get(k)]
        self._ignore_org = [re.compile(rx, re.I) for rx in rules.get("ignore_org_names", [])]
        self._legacy = rules.get("legacy", {})

    @classmethod
    def default(cls, asn_types: dict[int, str] | None = None) -> "Categorizer":
        rules = json.loads((resources.files("cirrus_ipinfo") / "data" / "category-rules.json").read_text())
        return cls(rules, PublicSuffixList.default(), asn_types)

    # -- helpers
    def _by_domain(self, host: str, domain: str | None) -> tuple[str, str | None] | None:
        if domain and domain in self._domain_over:
            return self._domain_over[domain]
        labels = host.split(".")
        for pattern, cat, sub in self._suffix_rules:
            if _suffix_matches(pattern, labels):
                return (cat, sub)
        return None

    def clean_org(self, org: str | None) -> str | None:
        """Registry org name, or None when it's really a maintainer handle (``HYDRA-MNT``) or placeholder."""
        if not org or not org.strip():
            return None
        org = org.strip()
        return None if any(rx.search(org) for rx in self._ignore_org) else org

    @staticmethod
    def as_description(as_name: str | None) -> str | None:
        """``'GOOGLE - Google LLC'`` → ``'Google LLC'``; ``'OVH OVH SAS'`` → ``'OVH SAS'``."""
        if not as_name:
            return None
        handle, _, rest = as_name.partition(" ")
        rest = rest.lstrip("- ").strip()
        return rest or None    # a bare handle ("EXAMPLE-AS") says nothing about the organisation

    def _org_texts(self, rec: EnrichmentRecord, *, whole_as_name: bool) -> list[str]:
        """Registry org, then the AS name. Keywords use the whole AS name (handles such as
        ``SPACEX-STARLINK`` or ``…-IDC`` are informative); the legal-form check uses only
        the description, because handles end in ``-AS``."""
        as_text = rec.as_name if whole_as_name else self.as_description(rec.as_name)
        texts = [self.clean_org(rec.network.org if rec.network else None), as_text]
        return [t for t in texts if t]

    def _by_org_keywords(self, texts: list[str]) -> tuple[str, str] | None:
        for text in texts:
            for rx, cat, sub in self._org_kw:
                if rx.search(text):
                    return (cat, sub)
        return None

    def _by_ptr_labels(self, host: str | None) -> tuple[str, str] | None:
        if not host:
            return None
        tokens = {re.sub(r"\d+$", "", t) for t in re.split(r"[.-]", host)}
        tokens.discard("")
        for words, cat, sub in self._ptr_labels:
            if tokens & words:
                return (cat, sub)
        return None

    def _is_company(self, texts: list[str]) -> bool:
        return any(rx.search(t) for rx in self._company for t in texts)

    def legacy(self, rec: EnrichmentRecord, host: str | None, domain: str | None) -> str:
        lg = self._legacy
        if rec.ptr_status in ("timeout", "servfail"):
            return lg.get("lookup_failed", "N/A")
        if not host:
            return lg.get("no_ptr", "-")
        if domain and domain in lg.get("domains", {}):
            return lg["domains"][domain]
        return lg.get("tld", {}).get(host.rsplit(".", 1)[-1], lg.get("other", "OTHER"))

    # -- main
    def categorize(self, rec: EnrichmentRecord) -> CategoryResult:
        host = rec.ptr.rstrip(".").lower() if rec.ptr else None
        domain = self.psl.registrable_domain(host)
        org_name = self.clean_org(rec.network.org if rec.network else None) or rec.as_name
        confirmed = bool(host and rec.fcrdns)

        def out(cat: str, sub: str | None, basis: str) -> CategoryResult:
            return CategoryResult(cat, sub, domain, org_name, basis, self.legacy(rec, host, domain))

        if rec.special_purpose:
            return out("special", _slug(rec.special_purpose), "special")

        addr = normalize(rec.ip)
        if any(addr in n for n in self._node_nets):
            return out("internal", self._node_sub, "k8s_node_cidr")
        if confirmed and self._node_ptr and self._node_ptr.match(host):
            return out("internal", self._node_sub, "k8s_node_ptr")
        if rec.origin_asn in self._int_asns:
            return out("internal", self._int_sub, "internal_asn")
        if any(addr in n for n in self._int_nets):
            return out("internal", self._int_sub, "internal_cidr")
        if confirmed and domain in self._int_domains:
            return out("internal", self._int_sub, "internal_domain")

        if rec.tor_exit:
            return out("anonymizer", "tor", "tor_exit_list")
        if rec.cloud_provider:
            return out("cloud", rec.cloud_provider, "cloud_range")

        if confirmed:
            if domain in self._domain_over:
                return out(*self._domain_over[domain], "domain_override")
        if rec.origin_asn in self._asn_over and not (confirmed and self._by_domain(host, domain)):
            return out(*self._asn_over[rec.origin_asn], "asn_override")
        if confirmed:
            hit = self._by_domain(host, domain)
            if hit:
                return out(*hit, "ptr_suffix")

        pdb_type = self.asn_types.get(rec.origin_asn) if rec.origin_asn is not None else None
        if pdb_type in self._pdb:
            return out(*self._pdb[pdb_type], "asn_type")

        hit = self._by_org_keywords(self._org_texts(rec, whole_as_name=True))
        if hit:
            return out(*hit, "org_keyword")

        hit = self._by_ptr_labels(host)
        if hit:
            return out(*hit, "ptr_label")

        if host and not confirmed:
            hit = self._by_domain(host, domain)
            if hit:
                return out(*hit, "ptr_suffix_unconfirmed")

        if self._is_company(self._org_texts(rec, whole_as_name=False)):
            return out("commercial", "company", "company_name")

        return out("unknown", "unclassified" if host else "no_ptr", "none")
