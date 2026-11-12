import itertools

import pytest
from packaging.version import Version

from pip_audit._merge import find_disagreements, merge_vulnerability_results
from pip_audit._service.interface import VulnerabilityEvidence, VulnerabilityResult


def _result(
    id,
    source,
    fix_versions,
    aliases=(),
    description="desc",
    withdrawn=None,
):
    return VulnerabilityResult(
        id=id,
        description=description,
        fix_versions=list(fix_versions),
        aliases=set(aliases),
        source=source,
        withdrawn=withdrawn,
        evidence=(
            VulnerabilityEvidence(
                id=id,
                source=source,
                description=description,
                fix_versions=tuple(fix_versions),
                aliases=frozenset(aliases),
                withdrawn=withdrawn,
            ),
        ),
    )


def test_merge_transitive_aliases_collapses_chain():
    # CVE -> GHSA and GHSA -> PYSEC share no direct identifier, but the
    # shared GHSA makes all three records one transitively-linked finding.
    vulns = [
        _result("CVE-2025-0001", "pypi", [Version("1.5.0")], aliases=("GHSA-aaaa-1111-bbbb",)),
        _result(
            "GHSA-aaaa-1111-bbbb",
            "osv",
            [Version("1.4.0"), Version("1.5.0")],
            aliases=("PYSEC-2025-9",),
        ),
        _result("PYSEC-2025-9", "ecosystems", [Version("1.5.0")]),
    ]

    merged = merge_vulnerability_results(vulns)

    assert len(merged) == 1
    result = merged[0]
    # PYSEC takes priority as the primary identifier.
    assert result.id == "PYSEC-2025-9"
    assert result.aliases == {"CVE-2025-0001", "GHSA-aaaa-1111-bbbb"}
    # Fix versions are the union across every still-active record.
    assert result.fix_versions == [Version("1.4.0"), Version("1.5.0")]
    # Each original record is retained as per-source evidence.
    assert [entry.source for entry in result.evidence] == [
        "ecosystems",
        "osv",
        "pypi",
    ]


@pytest.mark.parametrize("order", itertools.permutations(range(3)))
def test_merge_is_order_independent(order):
    vulns = [
        _result("CVE-2025-0001", "pypi", [Version("1.5.0")], aliases=("GHSA-x",)),
        _result("GHSA-x", "osv", [Version("1.4.0")], aliases=("PYSEC-1",)),
        _result("CVE-2025-9999", "pypi", [Version("2.0.0")]),
    ]

    reference = merge_vulnerability_results(vulns)
    shuffled = merge_vulnerability_results([vulns[i] for i in order])

    assert shuffled == reference
    assert [result.id for result in shuffled] == ["PYSEC-1", "CVE-2025-9999"]


def test_merge_does_not_cross_package_boundaries():
    # The same GHSA alias on two otherwise-distinct findings must not merge
    # them when they are audited as separate package-version groups. The
    # auditor calls the merge once per dependency, so simulate that directly.
    pkg_one = [
        _result("GHSA-shared", "osv", [Version("1.0.1")], description="pkg-one"),
    ]
    pkg_two = [
        _result("GHSA-shared", "osv", [Version("2.0.1")], description="pkg-two"),
    ]

    merged_one = merge_vulnerability_results(pkg_one)
    merged_two = merge_vulnerability_results(pkg_two)

    assert len(merged_one) == 1
    assert len(merged_two) == 1
    assert merged_one[0].fix_versions == [Version("1.0.1")]
    assert merged_two[0].fix_versions == [Version("2.0.1")]
    assert merged_one[0].evidence[0].description == "pkg-one"
    assert merged_two[0].evidence[0].description == "pkg-two"


def test_merge_drops_fully_withdrawn_group():
    vulns = [
        _result(
            "GHSA-gone",
            "osv",
            [],
            aliases=("CVE-2025-0002",),
            withdrawn="2026-01-01T00:00:00Z",
        ),
        _result(
            "CVE-2025-0002",
            "pypi",
            [Version("1.2.0")],
            withdrawn="2026-01-02T00:00:00Z",
        ),
    ]

    assert merge_vulnerability_results(vulns) == []


def test_merge_keeps_finding_when_one_source_withdrawn_but_other_active():
    vulns = [
        _result(
            "GHSA-live",
            "osv",
            [Version("1.3.0")],
            aliases=("CVE-2025-0003",),
            description="active advisory",
        ),
        _result(
            "CVE-2025-0003",
            "pypi",
            [Version("9.9.9")],
            withdrawn="2026-01-02T00:00:00Z",
            description="withdrawn advisory",
        ),
    ]

    merged = merge_vulnerability_results(vulns)

    assert len(merged) == 1
    result = merged[0]
    assert result.id == "CVE-2025-0003"
    assert result.withdrawn is None
    assert not result.is_withdrawn
    # The withdrawn record's (stale) fix version must not be treated as
    # actionable guidance; only the active OSV fix survives.
    assert result.fix_versions == [Version("1.3.0")]
    assert result.description == "active advisory"
    # Both records remain visible as evidence, with the PyPI one flagged.
    assert [entry.is_withdrawn for entry in result.evidence] == [False, True]


def test_merge_unions_fix_versions_when_one_source_has_none():
    vulns = [
        _result("GHSA-nofix", "osv", [], aliases=("CVE-2025-0004",)),
        _result("CVE-2025-0004", "pypi", [Version("1.6.0"), Version("1.7.0")]),
    ]

    merged = merge_vulnerability_results(vulns)

    assert len(merged) == 1
    assert merged[0].fix_versions == [Version("1.6.0"), Version("1.7.0")]


def test_find_disagreements_reports_fix_version_and_description_differences():
    result = merge_vulnerability_results(
        [
            _result(
                "GHSA-d",
                "osv",
                [Version("1.4.0")],
                aliases=("CVE-2025-0005",),
                description="osv wording",
            ),
            _result(
                "CVE-2025-0005",
                "pypi",
                [Version("1.5.0")],
                description="pypi wording",
            ),
        ]
    )[0]

    fields = {entry["field"] for entry in find_disagreements(result)}
    assert fields == {"fix_versions", "description"}


def test_find_disagreements_flags_withdrawn_evidence_only():
    result = merge_vulnerability_results(
        [
            _result("GHSA-w", "osv", [Version("1.3.0")], aliases=("CVE-2025-0006",)),
            _result(
                "CVE-2025-0006",
                "pypi",
                [Version("1.3.0")],
                withdrawn="2026-01-02T00:00:00Z",
            ),
        ]
    )[0]

    disagreements = find_disagreements(result)
    assert len(disagreements) == 1
    assert disagreements[0]["field"] == "withdrawn"
    assert disagreements[0]["source"] == "pypi"


def test_find_disagreements_empty_when_evidence_agrees():
    result = merge_vulnerability_results(
        [
            _result("GHSA-a", "osv", [Version("1.3.0")], aliases=("CVE-2025-0007",)),
            _result("CVE-2025-0007", "pypi", [Version("1.3.0")]),
        ]
    )[0]

    assert find_disagreements(result) == []


def test_duplicate_evidence_is_deduped_and_ordered_deterministically():
    # Two records from the same source sharing an id, with different detail
    # fields: both survive (they are distinct evidence) but their emitted
    # order must be fixed regardless of input ordering.
    first = _result("CVE-2025-0008", "pypi", [Version("1.2.0")], description="a")
    second = _result("CVE-2025-0008", "pypi", [Version("1.3.0")], description="b")

    merged_forward = merge_vulnerability_results([first, second])[0]
    merged_reverse = merge_vulnerability_results([second, first])[0]

    assert merged_forward == merged_reverse
    assert [entry.description for entry in merged_forward.evidence] == ["a", "b"]
    assert [entry.fix_versions for entry in merged_forward.evidence] == [
        (Version("1.2.0"),),
        (Version("1.3.0"),),
    ]
    assert merged_forward.fix_versions == [Version("1.2.0"), Version("1.3.0")]
