"""
Functionality for resolving fixed versions of dependencies.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, cast

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedConstraint:
    """
    Represents the version constraints that a dependency source imposes on a package.

    `specifiers` are the individual PEP 440 specifier sets that apply to the package in the
    current environment. A candidate version must be contained by every one of them.

    `sources` are human-readable descriptions of where each specifier came from (for example,
    the requirements file and line that declared it). They are used to explain conflicts.

    `allow_prereleases` controls whether prerelease candidates may satisfy the constraints,
    mirroring `pip`'s prerelease policy.
    """

    specifiers: tuple[SpecifierSet, ...]
    sources: tuple[str, ...]
    allow_prereleases: bool = False

    def contains(self, version: Version) -> bool:
        """
        Return whether the given version satisfies every specifier in this constraint.
        """
        return all(
            specifier.contains(version, prereleases=self.allow_prereleases)
            for specifier in self.specifiers
        )

    def describe(self) -> str:
        """
        Render the constraint and its sources for inclusion in a conflict message.
        """
        rendered = ", ".join(str(specifier) for specifier in self.specifiers)
        origins = ", ".join(self.sources)
        return f"{rendered} (from {origins})"


# A mapping of canonical package names to the constraints imposed on them.
Constraints = dict[str, ResolvedConstraint]


@dataclass(frozen=True)
class FixVersion:
    """
    Represents an abstract dependency fix version.

    This class cannot be constructed directly.
    """

    dep: ResolvedDependency

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:  # pragma: no cover
        """
        A stub constructor that always fails.
        """
        raise NotImplementedError

    def is_skipped(self) -> bool:
        """
        Check whether the `FixVersion` was unable to be resolved.
        """
        return self.__class__ is SkippedFixVersion


@dataclass(frozen=True)
class ResolvedFixVersion(FixVersion):
    """
    Represents a resolved fix version.
    """

    version: Version


@dataclass(frozen=True)
class SkippedFixVersion(FixVersion):
    """
    Represents a fix version that was unable to be resolved and therefore, skipped.
    """

    skip_reason: str


def resolve_fix_versions(
    service: VulnerabilityService,
    result: dict[Dependency, list[VulnerabilityResult]],
    state: AuditState = AuditState(),
    constraints: Constraints | None = None,
) -> Iterator[FixVersion]:
    """
    Resolves a mapping of dependencies to known vulnerabilities to a series of fix versions without
    known vulnerabilities.

    `constraints` optionally provides the version constraints that the dependency source imposes on
    each package. When supplied, a fix version is only chosen if it satisfies the package's
    constraints. If no fix version can satisfy both the vulnerabilities and the constraints, a
    `SkippedFixVersion` is yielded explaining the conflicting constraint instead.
    """
    constraints = constraints or {}
    for dep, vulns in result.items():
        if dep.is_skipped():
            continue
        if not vulns:
            continue
        dep = cast(ResolvedDependency, dep)
        try:
            version = _resolve_fix_version(service, dep, vulns, state, constraints)
            yield ResolvedFixVersion(dep, version)
        except FixResolutionImpossible as fri:
            skip_reason = str(fri)
            logger.debug(skip_reason)
            yield SkippedFixVersion(dep, skip_reason)


def _resolve_fix_version(
    service: VulnerabilityService,
    dep: ResolvedDependency,
    vulns: list[VulnerabilityResult],
    state: AuditState,
    constraints: Constraints,
) -> Version:
    # We need to upgrade to a fix version that satisfies all vulnerability results
    #
    # However, whenever we upgrade a dependency, we run the risk of introducing new vulnerabilities
    # so we need to run this in a loop and continue polling the vulnerability service on each
    # prospective resolved fix version
    current_version = dep.version
    current_vulns = vulns
    constraint = constraints.get(canonicalize_name(dep.name))
    while current_vulns:
        state.update_state(f"Resolving fix version for {dep.name}, checking {current_version}")

        def get_earliest_fix_version(d: ResolvedDependency, v: VulnerabilityResult) -> Version:
            # Consider the fix versions in ascending order so that we select the smallest
            # candidate that resolves the vulnerability, rather than blindly jumping to the
            # most recent release. Candidates that violate the project's constraints are skipped.
            for fix_version in sorted(v.fix_versions):
                if fix_version <= current_version:
                    continue
                if constraint is not None and not constraint.contains(fix_version):
                    continue
                return fix_version
            raise FixResolutionImpossible(
                _no_candidate_message(dep, v, constraint, current_version)
            )

        # We want to retrieve a version that potentially fixes all vulnerabilities
        current_version = max([get_earliest_fix_version(dep, v) for v in current_vulns])
        _, current_vulns = service.query(ResolvedDependency(dep.name, current_version))
    return current_version


def _no_candidate_message(
    dep: ResolvedDependency,
    vuln: VulnerabilityResult,
    constraint: ResolvedConstraint | None,
    current_version: Version,
) -> str:
    """
    Build the message used when no applicable fix version can be found.
    """
    candidates = [version for version in vuln.fix_versions if version > current_version]
    if not candidates or constraint is None:
        return (
            f"failed to fix dependency {dep.name} ({dep.version}), unable to find fix version "
            f"for vulnerability {vuln.id}"
        )

    candidate_str = ", ".join(str(version) for version in sorted(candidates))
    return (
        f"failed to fix dependency {dep.name} ({dep.version}), no fix version for vulnerability "
        f"{vuln.id} satisfies the project constraint {constraint.describe()}; "
        f"available fix versions: {candidate_str}"
    )


class FixResolutionImpossible(Exception):
    """
    Raised when `resolve_fix_versions` fails to find a fix version without known vulnerabilities
    """

    pass
