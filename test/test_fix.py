from __future__ import annotations

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._fix import (
    Constraints,
    ResolvedConstraint,
    ResolvedFixVersion,
    SkippedFixVersion,
    resolve_fix_versions,
)
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


def test_fix(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == ResolvedFixVersion(dep=dep, version=Version("1.1.0"))
    assert not fix_versions[0].is_skipped()


def test_fix_skipped_deps(vuln_service):
    dep = SkippedDependency(name="foo", skip_reason="skip-reason")
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_no_vulns(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {dep: []}
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_resolution_impossible(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == SkippedFixVersion(
        dep=dep,
        skip_reason="failed to fix dependency foo (0.5.0), unable to find fix version for "
        "vulnerability fake-id",
    )
    assert fix_versions[0].is_skipped()


class _StaticService(VulnerabilityService):
    """
    A vulnerability service driven entirely by an in-memory vulnerability table.

    `vulns_by_version` maps a version to the vulnerabilities reported for that version. Any
    version absent from the table is treated as clean.
    """

    def __init__(self, vulns_by_version: dict[Version, list[VulnerabilityResult]]):
        self._vulns_by_version = vulns_by_version

    def query(self, spec):
        return spec, list(self._vulns_by_version.get(spec.version, []))


def _constraint(spec: str, *, allow_prereleases: bool = False) -> ResolvedConstraint:
    return ResolvedConstraint(
        specifiers=(SpecifierSet(spec),),
        sources=(f"requirements.txt ({spec})",),
        allow_prereleases=allow_prereleases,
    )


def test_fix_picks_smallest_candidate_without_constraints():
    # With several fix versions advertised, the smallest one greater than the current version is
    # chosen rather than jumping straight to the newest release.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("2.0.0"), Version("1.1.0"), Version("1.2.0")],
                aliases=set(),
            )
        ]
    }
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result))
    assert fix_versions == [ResolvedFixVersion(dep=dep, version=Version("1.1.0"))]


def test_fix_multiple_vulnerabilities_chooses_satisfying_candidate():
    # Two vulnerabilities with overlapping fix versions. The chosen version must be the smallest
    # that clears both vulnerabilities while staying inside the constraint.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-A",
                description="",
                fix_versions=[
                    Version("1.1.0"),
                    Version("1.4.0"),
                    Version("1.5.0"),
                    Version("2.0.0"),
                ],
                aliases=set(),
            ),
            VulnerabilityResult(
                id="VULN-B",
                description="",
                fix_versions=[Version("1.4.0"), Version("1.5.0"), Version("2.0.0")],
                aliases=set(),
            ),
        ]
    }
    constraints: Constraints = {"foo": _constraint(">=1.4.0,<=1.5.0")}
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    # Both vulnerabilities need >=1.4.0; 1.4.0 is the smallest version that fixes both and that
    # satisfies the bound.
    assert fix_versions == [ResolvedFixVersion(dep=dep, version=Version("1.4.0"))]


def test_fix_constraint_skips_blocking_candidate_and_uses_allowed_one():
    # The earliest fix version (1.1.0) violates ">=1.3.0", so resolution must skip it and pick the
    # next allowed candidate instead.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("1.1.0"), Version("1.3.0"), Version("2.0.0")],
                aliases=set(),
            )
        ]
    }
    constraints: Constraints = {"foo": _constraint(">=1.3.0")}
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    assert fix_versions == [ResolvedFixVersion(dep=dep, version=Version("1.3.0"))]


def test_fix_conflicting_constraint_is_skipped_with_reason():
    # Every fix version is ruled out by the constraint, so the dependency must be skipped and the
    # reported reason must name the blocking constraint and the rejected fix versions.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("2.0.0"), Version("3.0.0")],
                aliases=set(),
            )
        ]
    }
    constraints: Constraints = {"foo": _constraint("<2.0.0")}
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    assert len(fix_versions) == 1
    skipped = fix_versions[0]
    assert isinstance(skipped, SkippedFixVersion)
    assert skipped.is_skipped()
    assert "VULN-1" in skipped.skip_reason
    assert "<2.0.0" in skipped.skip_reason
    assert "2.0.0" in skipped.skip_reason and "3.0.0" in skipped.skip_reason
    assert "requirements.txt" in skipped.skip_reason


def test_fix_prerelease_candidate_excluded_by_default():
    # The only in-constraint fix is a prerelease. Prereleases are excluded unless explicitly
    # allowed, so this should be reported as a conflict.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("2.0.0a1")],
                aliases=set(),
            )
        ]
    }
    constraints: Constraints = {"foo": _constraint("<3.0.0")}
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    assert len(fix_versions) == 1
    assert isinstance(fix_versions[0], SkippedFixVersion)


def test_fix_prerelease_candidate_allowed_when_enabled():
    # When prereleases are permitted, the prerelease fix version is accepted.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("2.0.0a1")],
                aliases=set(),
            )
        ]
    }
    constraints: Constraints = {"foo": _constraint("<3.0.0", allow_prereleases=True)}
    service = _StaticService({})
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    assert fix_versions == [ResolvedFixVersion(dep=dep, version=Version("2.0.0a1"))]


def test_fix_constraint_keeps_resolving_newly_introduced_vulnerability():
    # The smallest allowed candidate still has a vulnerability. Resolution must keep advancing to
    # the next allowed, clean version instead of stopping early.
    dep = ResolvedDependency(name="foo", version=Version("1.0.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="VULN-1",
                description="",
                fix_versions=[Version("1.1.0"), Version("1.2.0")],
                aliases=set(),
            )
        ]
    }
    service = _StaticService(
        {
            Version("1.1.0"): [
                VulnerabilityResult(
                    id="VULN-2",
                    description="",
                    fix_versions=[Version("1.2.0")],
                    aliases=set(),
                )
            ]
        }
    )
    constraints: Constraints = {"foo": _constraint("<2.0.0")}
    fix_versions = list(resolve_fix_versions(service, result, constraints=constraints))
    assert fix_versions == [ResolvedFixVersion(dep=dep, version=Version("1.2.0"))]
