"""
Merging of per-service vulnerability results into de-duplicated findings.

The same underlying vulnerability is commonly reported under several
identifiers (e.g. a `CVE` and a `GHSA` alias). This module collapses such
overlapping results into a single `VulnerabilityResult` while preserving the
per-package-version evidence (source, description, fix versions and
withdrawal state) behind each merge.

The merge is purely order-independent: feeding the same input in any order
always produces an identical result. This is achieved by grouping results
with a union-find over their shared identifiers and by sorting every
derived collection deterministically.
"""

from __future__ import annotations

from packaging.version import Version

from pip_audit._service.interface import (
    VulnerabilityEvidence,
    VulnerabilityID,
    VulnerabilityResult,
)


def _identifier_rank(identifier: VulnerabilityID) -> int:
    # Keep PYSEC identifiers first, then CVEs, mirroring
    # `VulnerabilityResult.create`'s prioritization.
    if identifier.startswith("PYSEC"):
        return 0
    if identifier.startswith("CVE"):
        return 1
    return 2


def _identifier_sort_key(identifier: VulnerabilityID) -> tuple[int, str]:
    return _identifier_rank(identifier), identifier


def _evidence_sort_key(
    evidence: VulnerabilityEvidence,
) -> tuple[str, str, str, tuple[Version, ...], str]:
    # A total-order key: ties on `(source, id)` are broken deterministically by
    # the remaining fields so the order never depends on the input sequence.
    return (
        evidence.source,
        evidence.id,
        evidence.description,
        evidence.fix_versions,
        evidence.withdrawn or "",
    )


def _result_primary_sort_key(result: VulnerabilityResult) -> tuple[int, str, str]:
    return _identifier_rank(result.id), result.id, result.source


class _DisjointSet:
    """
    A minimal union-find structure keyed by integer indices.
    """

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression.
        while self._parent[item] != item:
            parent = self._parent[item]
            self._parent[item] = root
            item = parent
        return root

    def union(self, left: int, right: int) -> None:
        self._parent[self.find(left)] = self.find(right)


def _group_aliases(
    vulns: list[VulnerabilityResult],
) -> list[list[VulnerabilityResult]]:
    """
    Group results whose `{id, *aliases}` sets transitively intersect.
    """
    groups = _DisjointSet(len(vulns))
    # Map every known identifier to the index of the first result that
    # introduced it; subsequent results sharing that identifier are united
    # with that result's component.
    identifier_owner: dict[VulnerabilityID, int] = {}
    for index, vuln in enumerate(vulns):
        for identifier in vuln.all_ids():
            owner = identifier_owner.get(identifier)
            if owner is None:
                identifier_owner[identifier] = index
            else:
                groups.union(owner, index)

    components: dict[int, list[VulnerabilityResult]] = {}
    for index, vuln in enumerate(vulns):
        components.setdefault(groups.find(index), []).append(vuln)

    return list(components.values())


def _merge_group(group: list[VulnerabilityResult]) -> VulnerabilityResult:
    """
    Merge a single group of alias-overlapping results into one result.
    """
    all_identifiers: set[VulnerabilityID] = set()
    evidence: list[VulnerabilityEvidence] = []
    published = None

    for result in group:
        all_identifiers.update(result.all_ids())
        # A result produced by a service carries its own evidence. Results
        # constructed directly (e.g. in tests) may carry none, so fall back
        # to synthesizing evidence from the result itself.
        if result.evidence:
            evidence.extend(result.evidence)
        else:
            evidence.append(
                VulnerabilityEvidence(
                    id=result.id,
                    source=result.source,
                    description=result.description,
                    fix_versions=tuple(result.fix_versions),
                    aliases=frozenset(result.aliases),
                    withdrawn=result.withdrawn,
                )
            )
        if result.published is not None and (published is None or result.published < published):
            published = result.published

    # Deterministic, de-duplicated evidence.
    evidence = sorted(set(evidence), key=_evidence_sort_key)

    # Pick the primary identifier from *all* known identifiers (including
    # aliases), so a PYSEC/CVE reported only as an alias still wins over a
    # GHSA used as a record ID. This is independent of input ordering.
    primary_id = min(all_identifiers, key=_identifier_sort_key)
    aliases = set(all_identifiers) - {primary_id}

    # Fix versions come only from records that are still active: a withdrawn
    # record's fix versions must not be treated as actionable guidance.
    fix_versions = sorted(
        {
            version
            for entry in evidence
            if not entry.is_withdrawn
            for version in entry.fix_versions
        }
    )

    active_evidence = [entry for entry in evidence if not entry.is_withdrawn]
    if active_evidence:
        description = min(active_evidence, key=_evidence_sort_key).description
        source = min(active_evidence, key=_evidence_sort_key).source
        withdrawn = None
    else:
        description = min(evidence, key=_evidence_sort_key).description
        source = min(evidence, key=_evidence_sort_key).source
        withdrawn = min(evidence, key=_evidence_sort_key).withdrawn

    return VulnerabilityResult(
        id=primary_id,
        description=description,
        fix_versions=fix_versions,
        aliases=aliases,
        published=published,
        source=source,
        withdrawn=withdrawn,
        evidence=tuple(evidence),
    )


def merge_vulnerability_results(
    vulns: list[VulnerabilityResult],
) -> list[VulnerabilityResult]:
    """
    Merge alias-overlapping vulnerability results into de-duplicated findings.

    Results that do not share any identifier are returned as standalone
    findings. Groups whose every record has been withdrawn are dropped
    entirely; a group with at least one active record is retained, with the
    withdrawn records kept as evidence. The returned list and every collection
    within it are sorted deterministically, so the output does not depend on
    the ordering of `vulns`.
    """
    merged = [_merge_group(group) for group in _group_aliases(vulns)]
    merged = [result for result in merged if not result.is_withdrawn]
    merged.sort(key=lambda result: (_result_primary_sort_key(result),))
    return merged


def find_disagreements(result: VulnerabilityResult) -> list[dict[str, object]]:
    """
    Report the fields on which the evidence for a merged result still differs.

    This surfaces the cases that merging cannot resolve on its own, such as
    one source omitting a fix version that another source provides, or the
    sources carrying different descriptions. Withdrawn records are reported
    separately and never treated as conflicting guidance. The returned list is
    sorted deterministically.
    """
    active = sorted(
        (entry for entry in result.evidence if not entry.is_withdrawn),
        key=_evidence_sort_key,
    )
    disagreements: list[dict[str, object]] = []

    if len(active) >= 2:
        fix_version_sets = {entry.fix_versions for entry in active}
        if len(fix_version_sets) > 1:
            disagreements.append(
                {
                    "field": "fix_versions",
                    "evidence": [
                        {
                            "source": entry.source,
                            "id": entry.id,
                            "fix_versions": [str(version) for version in entry.fix_versions],
                        }
                        for entry in active
                    ],
                }
            )

        descriptions = {entry.description for entry in active}
        if len(descriptions) > 1:
            disagreements.append(
                {
                    "field": "description",
                    "evidence": [
                        {
                            "source": entry.source,
                            "id": entry.id,
                            "description": entry.description,
                        }
                        for entry in active
                    ],
                }
            )

    withdrawn = sorted(
        (entry for entry in result.evidence if entry.is_withdrawn),
        key=_evidence_sort_key,
    )
    for entry in withdrawn:
        disagreements.append(
            {
                "field": "withdrawn",
                "source": entry.source,
                "id": entry.id,
                "withdrawn": entry.withdrawn,
            }
        )

    return disagreements
