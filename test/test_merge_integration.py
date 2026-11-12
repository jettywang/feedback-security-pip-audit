"""
End-to-end merging behavior built from fake OSV/PyPI responses.

These tests feed hand-crafted service payloads (alias transitivity, the same
alias appearing for different packages, withdrawn records, and missing fix
versions) through the real services, the `Auditor` merge step and the JSON
formatter, and assert that the JSON explains both merges and remaining
disagreements while staying stable under input reordering.
"""

from __future__ import annotations

import itertools
import json

import pretend  # type: ignore
import pytest
from packaging.version import Version

import pip_audit._format as format
import pip_audit._service as service
from pip_audit._audit import Auditor
from pip_audit._dependency_source.interface import DependencySource


class _ListSource(DependencySource):
    def __init__(self, deps):
        self._deps = deps

    def collect(self):
        return iter(list(self._deps))

    def fix(self, _) -> None:
        raise NotImplementedError


def _osv(payload):
    osv = service.OsvService()
    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    osv.session.post = pretend.call_recorder(lambda *a, **kw: response)
    return osv


def _pypi(payload):
    pypi = service.PyPIService(cache_dir=pretend.stub())
    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    pypi.session.get = pretend.call_recorder(lambda *a, **kw: response)
    return pypi


class _CombinedService(service.VulnerabilityService):
    """
    Queries two backing services and concatenates their per-dependency results,
    mimicking an internal roll-up of OSV and PyPI feeds before merging.
    """

    def __init__(self, *backing):
        self._backing = backing

    def query(self, spec):
        combined = []
        for backing in self._backing:
            _, results = backing.query(spec)
            combined.extend(results)
        return spec, combined


def _audit(service_backend, deps):
    source = _ListSource(deps)
    return dict(Auditor(service_backend).audit(source))


def test_alias_transitivity_merges_cve_ghsa_pysec_and_preserves_evidence():
    dep = service.ResolvedDependency("pkg-a", Version("1.0.0"))

    osv_payload = {
        "vulns": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2025-0001", "PYSEC-2025-7"],
                "summary": "OSV summary",
                "affected": [
                    {
                        "package": {"name": "pkg-a", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "1.4.0"}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    pypi_payload = {
        "vulnerabilities": [
            {
                "id": "CVE-2025-0001",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
                "summary": "PyPI summary",
                "fixed_in": ["1.5.0"],
            }
        ]
    }

    results = _audit(_CombinedService(_osv(osv_payload), _pypi(pypi_payload)), [dep])
    vulns = results[dep]

    assert len(vulns) == 1
    merged = vulns[0]
    # PYSEC is only present as an alias but still becomes the primary ID.
    assert merged.id == "PYSEC-2025-7"
    assert merged.aliases == {"CVE-2025-0001", "GHSA-aaaa-bbbb-cccc"}
    # Fix versions from both active sources are retained and ordered.
    assert merged.fix_versions == [Version("1.4.0"), Version("1.5.0")]
    assert {entry.source for entry in merged.evidence} == {"osv", "pypi"}

    rendered = json.loads(format.JsonFormat(True, True).format(results, []))
    vuln_json = rendered["dependencies"][0]["vulns"][0]
    assert vuln_json["merged"] is True
    assert {entry["source"] for entry in vuln_json["evidence"]} == {"osv", "pypi"}
    # The two sources disagree on fix versions and descriptions; both surface.
    disagreement_fields = {entry["field"] for entry in vuln_json["disagreements"]}
    assert disagreement_fields == {"fix_versions", "description"}


def test_same_alias_for_different_packages_stays_separate():
    pkg_one = service.ResolvedDependency("pkg-one", Version("1.0.0"))
    pkg_two = service.ResolvedDependency("pkg-two", Version("2.0.0"))

    osv = _osv(
        {
            "vulns": [
                {
                    "id": "GHSA-shared-alias-0001",
                    "aliases": ["CVE-2025-7777"],
                    "summary": "shared alias, distinct ranges",
                    "affected": [
                        {
                            "package": {"name": "pkg-one", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                                }
                            ],
                        },
                        {
                            "package": {"name": "pkg-two", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.1"}],
                                }
                            ],
                        },
                    ],
                }
            ]
        }
    )

    results = _audit(osv, [pkg_one, pkg_two])

    assert {dep.canonical_name for dep in results} == {"pkg-one", "pkg-two"}
    by_name = {dep.canonical_name: vulns for dep, vulns in results.items()}
    assert by_name["pkg-one"][0].fix_versions == [Version("1.0.1")]
    assert by_name["pkg-two"][0].fix_versions == [Version("2.0.1")]
    # Each package keeps its own evidence despite the shared identifier.
    assert by_name["pkg-one"][0].id == by_name["pkg-two"][0].id == "CVE-2025-7777"


def test_withdrawn_by_one_source_keeps_active_other_source_with_evidence():
    dep = service.ResolvedDependency("pkg-b", Version("1.0.0"))

    osv = _osv(
        {
            "vulns": [
                {
                    "id": "GHSA-withdrawn-0001",
                    "aliases": ["CVE-2025-0002"],
                    "withdrawn": "2026-01-01T00:00:00Z",
                }
            ]
        }
    )
    pypi = _pypi(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2025-0002",
                    "aliases": ["GHSA-withdrawn-0001"],
                    "summary": "still affected",
                    "fixed_in": ["1.2.0"],
                }
            ]
        }
    )

    results = _audit(_CombinedService(osv, pypi), [dep])
    vulns = results[dep]

    assert len(vulns) == 1
    result = vulns[0]
    assert result.withdrawn is None
    assert not result.is_withdrawn
    assert result.fix_versions == [Version("1.2.0")]
    withdrawn_evidence = [entry for entry in result.evidence if entry.is_withdrawn]
    assert len(withdrawn_evidence) == 1
    assert withdrawn_evidence[0].source == "osv"

    rendered = json.loads(format.JsonFormat(True, True).format(results, []))
    vuln_json = rendered["dependencies"][0]["vulns"][0]
    assert vuln_json["merged"] is True
    assert any(
        disagreement["field"] == "withdrawn"
        and disagreement["source"] == "osv"
        for disagreement in vuln_json["disagreements"]
    )


def test_withdrawn_by_all_sources_is_dropped():
    dep = service.ResolvedDependency("pkg-c", Version("1.0.0"))

    osv = _osv(
        {
            "vulns": [
                {
                    "id": "GHSA-dead-0001",
                    "aliases": ["CVE-2025-0003"],
                    "withdrawn": "2026-01-01T00:00:00Z",
                }
            ]
        }
    )
    pypi = _pypi(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2025-0003",
                    "aliases": ["GHSA-dead-0001"],
                    "summary": "withdrawn here too",
                    "fixed_in": ["1.2.0"],
                    "withdrawn": "2026-01-02T00:00:00Z",
                }
            ]
        }
    )

    results = _audit(_CombinedService(osv, pypi), [dep])
    assert results[dep] == []


def test_missing_fix_version_in_one_source_uses_the_other():
    dep = service.ResolvedDependency("pkg-d", Version("1.0.0"))

    osv = _osv(
        {
            "vulns": [
                {
                    "id": "GHSA-nofix-0001",
                    "aliases": ["CVE-2025-0004"],
                    "summary": "no range, hence no fix",
                    "affected": [
                        {
                            "package": {"name": "pkg-d", "ecosystem": "PyPI"},
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        }
    )
    pypi = _pypi(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2025-0004",
                    "aliases": ["GHSA-nofix-0001"],
                    "summary": "has a fix",
                    "fixed_in": ["1.6.0"],
                }
            ]
        }
    )

    results = _audit(_CombinedService(osv, pypi), [dep])
    result = results[dep][0]

    assert result.fix_versions == [Version("1.6.0")]
    evidence_by_source = {entry.source: entry for entry in result.evidence}
    assert evidence_by_source["osv"].fix_versions == ()
    assert [str(version) for version in evidence_by_source["pypi"].fix_versions] == ["1.6.0"]

    rendered = json.loads(format.JsonFormat(False, False).format(results, []))
    vuln_json = rendered["dependencies"][0]["vulns"][0]
    assert vuln_json["fix_versions"] == ["1.6.0"]
    assert any(
        disagreement["field"] == "fix_versions"
        for disagreement in vuln_json["disagreements"]
    )


@pytest.mark.parametrize("order", itertools.permutations(range(2)))
def test_json_output_is_stable_under_reordering(order):
    dep = service.ResolvedDependency("pkg-e", Version("1.0.0"))

    records = [
        _osv(
            {
                "vulns": [
                    {
                        "id": "GHSA-order-0001",
                        "aliases": ["CVE-2025-0005"],
                        "summary": "osv wording",
                        "affected": [
                            {
                                "package": {"name": "pkg-e", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "1.4.0"}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        _pypi(
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-2025-0005",
                        "aliases": ["GHSA-order-0001"],
                        "summary": "pypi wording",
                        "fixed_in": ["1.5.0"],
                    }
                ]
            }
        ),
    ]

    def render(backing):
        results = _audit(_CombinedService(*backing), [dep])
        return format.JsonFormat(True, True).format(results, [])

    reference = render(list(records))
    shuffled = render([records[i] for i in order])

    assert json.loads(shuffled) == json.loads(reference)
    # Aliases and evidence must be emitted in a fixed order.
    parsed = json.loads(shuffled)
    vuln_json = parsed["dependencies"][0]["vulns"][0]
    assert vuln_json["aliases"] == sorted(vuln_json["aliases"])
    assert [entry["source"] for entry in vuln_json["evidence"]] == sorted(
        entry["source"] for entry in vuln_json["evidence"]
    )
