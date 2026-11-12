"""
A strict, read-only dependency source for `requirements.txt`-formatted files.

This source is intended for auditing uploaded requirement manifests: it only
ever audits requirements that are pinned to an exact version (`name==version`)
and it never resolves, downloads, installs, or builds anything. Lines that
would require resolution or building (VCS, editable, local path, sdist/wheel,
or URL requirements) and lines that are not exactly pinned are reported as
skipped dependencies, each with a human-readable reason.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pip_requirements_parser import InstallRequirement, OptionLine, RequirementsFile

from pip_audit._dependency_source import DependencyFixError, DependencySource
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)

_REMOTE_INCLUDE_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


@dataclass
class _ParsedManifests:
    """
    The fully parsed contents of a set of requirement manifests.
    """

    requirements: list[InstallRequirement] = field(default_factory=list)
    constraints: list[InstallRequirement] = field(default_factory=list)
    skipped: list[SkippedDependency] = field(default_factory=list)


class StrictRequirementSource(DependencySource):
    """
    A strict, read-only `requirements.txt` dependency source.

    Only requirements pinned to an exact version are collected for auditing;
    everything else is yielded as a `SkippedDependency` with a reason. No
    dependency resolution, installation, or building is ever performed.
    """

    def __init__(self, filenames: list[Path], *, state: AuditState = AuditState()) -> None:
        """
        Create a new `StrictRequirementSource`.

        `filenames` provides the list of requirement filepaths to parse. Local
        `-r`/`--requirement` includes and `-c`/`--constraint` files referenced
        by these files are followed (recursively); remote includes are not.

        `state` is an `AuditState` to use for state callbacks.
        """
        self._filenames = filenames
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all auditable dependencies discovered by this source.

        Yields `ResolvedDependency` for each requirement pinned to an exact
        version and `SkippedDependency` (with a reason) for each line that
        cannot be audited read-only. Never raises for unparseable or
        unauditable lines.
        """
        manifests = self._parse_manifests()
        yield from manifests.skipped

        # Index exact-pin constraints by canonical package name. A constraint
        # only makes an otherwise unpinned requirement auditable if it pins an
        # exact version; conflicting pins make the constraint unusable.
        constraint_pins: dict[str, Version | None] = {}
        for req in manifests.constraints:
            if req.name is None or not _marker_applies(req):
                continue
            pinned = _exact_pin(req)
            if pinned is None:
                continue
            canonical = canonicalize_name(req.name)
            previous = constraint_pins.setdefault(canonical, pinned)
            if previous != pinned:
                constraint_pins[canonical] = None

        seen: dict[str, Version] = {}
        for req in manifests.requirements:
            # Requirements whose markers don't apply to this environment are
            # not part of the audited set at all.
            if not _marker_applies(req):
                continue

            name = req.name or req.requirement_line.line

            if req.is_editable:
                yield SkippedDependency(
                    name=name,
                    skip_reason=_reason(
                        req, "editable requirement cannot be audited without building it"
                    ),
                )
                continue
            if req.is_vcs_url or req.is_url or req.is_name_at_url:
                yield SkippedDependency(
                    name=name,
                    skip_reason=_reason(
                        req,
                        "URL/VCS requirement cannot be audited without downloading "
                        "and building it",
                    ),
                )
                continue
            if req.is_local_path or req.is_archive or req.is_wheel:
                yield SkippedDependency(
                    name=name,
                    skip_reason=_reason(
                        req, "local file requirement cannot be audited without building it"
                    ),
                )
                continue
            if req.req is None or req.name is None:
                yield SkippedDependency(
                    name=name,
                    skip_reason=_reason(req, "could not determine a package name"),
                )
                continue

            pinned = _exact_pin(req)
            if pinned is None:
                constrained = constraint_pins.get(canonicalize_name(req.name))
                if constrained is None:
                    yield SkippedDependency(
                        name=name,
                        skip_reason=_reason(req, "requirement is not pinned to an exact version"),
                    )
                    continue
                pinned = constrained

            canonical = canonicalize_name(req.name)
            previous = seen.get(canonical)
            if previous is not None:
                if previous != pinned:
                    yield SkippedDependency(
                        name=name,
                        skip_reason=_reason(
                            req,
                            f"requirement conflicts with an earlier pin "
                            f"({req.name}=={previous})",
                        ),
                    )
                continue
            seen[canonical] = pinned

            logger.debug(f"collected pinned dependency {req.name}=={pinned}")
            yield ResolvedDependency(req.name, pinned)

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        This source is read-only and never modifies its inputs.
        """
        raise DependencyFixError("the strict read-only requirement source does not support fixes")

    def _parse_manifests(self) -> _ParsedManifests:
        """
        Parse all input manifests, following local includes recursively.
        """
        manifests = _ParsedManifests()
        visited: set[tuple[Path, bool]] = set()
        # Each entry is a (path, is_constraint) pair: entries parsed from a
        # constraint file constrain versions rather than add dependencies.
        queue: list[tuple[Path, bool]] = [(filename, False) for filename in self._filenames]

        while queue:
            path, is_constraint = queue.pop(0)
            key = (path.absolute(), is_constraint)
            if key in visited:
                continue
            visited.add(key)

            if not path.is_file():
                manifests.skipped.append(
                    SkippedDependency(
                        name=str(path),
                        skip_reason="requirements file does not exist",
                    )
                )
                continue

            try:
                rf = RequirementsFile.from_file(path)
            except Exception as exc:
                manifests.skipped.append(
                    SkippedDependency(
                        name=str(path),
                        skip_reason=f"requirements file could not be parsed: {exc}",
                    )
                )
                continue

            for invalid in rf.invalid_lines:
                manifests.skipped.append(
                    SkippedDependency(
                        name=invalid.line,
                        skip_reason=(
                            f"invalid requirement at {invalid.filename}:"
                            f"{invalid.line_number}: {invalid.error_message}"
                        ),
                    )
                )

            for option in rf.options:
                # Includes within a constraint file are themselves constraints;
                # `-c`/`--constraint` references are always constraints.
                for include, include_is_constraint in [
                    *[(i, is_constraint) for i in option.options.get("requirements", [])],
                    *[(c, True) for c in option.options.get("constraints", [])],
                ]:
                    if _is_remote_include(include):
                        manifests.skipped.append(
                            SkippedDependency(
                                name=include,
                                skip_reason=_reason(
                                    option,
                                    "remote includes are not followed in read-only mode",
                                ),
                            )
                        )
                        continue
                    queue.append((path.parent / include, include_is_constraint))

            if is_constraint:
                manifests.constraints.extend(rf.requirements)
            else:
                manifests.requirements.extend(rf.requirements)

        return manifests


def _marker_applies(req: InstallRequirement) -> bool:
    return req.marker is None or req.marker.evaluate()


def _exact_pin(req: InstallRequirement) -> Version | None:
    """
    Return the exact version a requirement is pinned to, or `None` if the
    requirement is not pinned to exactly one version (e.g. ranges, wildcards,
    or no specifier at all).
    """
    pinned = req.get_pinned_version
    if pinned is None or "*" in pinned:
        return None
    try:
        return Version(pinned)
    except InvalidVersion:
        return None


def _is_remote_include(include: str) -> bool:
    return "://" in include or include.startswith(_REMOTE_INCLUDE_PREFIXES)


def _reason(req: InstallRequirement | OptionLine, reason: str) -> str:
    """
    Annotate a skip reason with the requirement's source location.
    """
    line = req.requirement_line
    if line is None or line.filename is None:
        return reason
    return f"{line.filename}:{line.line_number}: {reason}"
