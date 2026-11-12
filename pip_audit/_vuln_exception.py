"""
Scoped, time-limited exceptions to vulnerability reports.

Unlike the broad `--ignore-vuln` flag, which suppresses a vulnerability ID
across every package and version, a `VulnerabilityException` only suppresses a
report when all of its constraints match: the vulnerability ID (or one of its
aliases), the affected package, the package's version (via a PEP 440 version
specifier), and an optional expiration date.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from pip_audit._service.interface import Dependency, ResolvedDependency, VulnerabilityResult


class VulnerabilityExceptionError(ValueError):
    """
    Raised when a vulnerability exception specification cannot be parsed.
    """

    pass


@dataclass(frozen=True)
class VulnerabilityException:
    """
    A scoped exception to one or more vulnerability reports.

    An exception matches a report only when its vulnerability ID (or alias),
    package name, version range, and validity window all match.
    """

    id: str
    """
    The vulnerability ID to suppress, e.g. `CVE-2024-1234`. Matching is
    case-insensitive and also considers a result's aliases.
    """

    package: str
    """
    The PEP 503 canonicalized name of the package whose reports may be
    suppressed.
    """

    versions: SpecifierSet
    """
    A PEP 440 version specifier; only reports for versions it contains are
    suppressed.
    """

    expires: date | None = None
    """
    The last day on which the exception is valid, or `None` if it does not
    expire. An exception whose `expires` date is strictly before the current
    date no longer matches.
    """

    reason: str | None = None
    """
    An optional human-readable justification, retained in the audit report for
    every report that the exception suppresses.
    """

    def matches(
        self,
        dep: Dependency,
        vuln: VulnerabilityResult,
        now: date | None = None,
    ) -> bool:
        """
        Return whether this exception suppresses `vuln` for the given
        resolved dependency.

        All four constraints must agree: the package name, the version range,
        the vulnerability ID (or an alias), and the validity window.
        """
        if not isinstance(dep, ResolvedDependency):
            return False
        if dep.canonical_name != self.package:
            return False
        if dep.version not in self.versions:
            return False

        wanted = {self.id.upper()}
        observed = {vuln.id.upper(), *(alias.upper() for alias in vuln.aliases)}
        if not wanted & observed:
            return False

        if self.expires is not None:
            current = now if now is not None else date.today()
            if current > self.expires:
                return False

        return True

    def render_reason(self) -> str:
        """
        Render a human-readable justification for reports suppressed by this
        exception, including the user-supplied reason (if any) and the
        exception's scope.
        """
        scope = f"{self.package} {self.versions}"
        if self.expires is not None:
            scope += f", expires {self.expires.isoformat()}"

        if self.reason:
            return f"{self.reason} (exception for {self.id} on {scope})"
        return f"Exception for {self.id} on {scope}"


def parse_vulnerability_exception(spec: str) -> VulnerabilityException:
    """
    Parse a single vulnerability exception specification.

    The expected form is::

        ID:PACKAGE:VERSION_SPEC[:EXPIRES[:REASON]]

    where `ID` is a vulnerability ID (matched against result IDs and aliases),
    `PACKAGE` is the affected package, `VERSION_SPEC` is a PEP 440 specifier
    (such as `>=1.0,<2.0`), the optional `EXPIRES` is an ISO `YYYY-MM-DD`
    date, and the optional `REASON` is free text (it may itself contain
    colons). The first three fields are required.
    """
    parts = spec.split(":", 4)
    if len(parts) < 3:
        raise VulnerabilityExceptionError(
            f"invalid vulnerability exception {spec!r}: expected "
            "ID:PACKAGE:VERSION_SPEC[:EXPIRES[:REASON]]"
        )

    vuln_id, package, version_spec = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not vuln_id or not package or not version_spec:
        raise VulnerabilityExceptionError(
            f"invalid vulnerability exception {spec!r}: ID, package and version specifier "
            "must not be empty"
        )

    expires: date | None = None
    reason: str | None = None
    if len(parts) >= 4 and parts[3].strip():
        try:
            expires = date.fromisoformat(parts[3].strip())
        except ValueError as exc:
            raise VulnerabilityExceptionError(
                f"invalid vulnerability exception {spec!r}: expiration must be a YYYY-MM-DD date"
            ) from exc
    if len(parts) == 5 and parts[4].strip():
        reason = parts[4].strip()

    try:
        versions = SpecifierSet(version_spec)
    except Exception as exc:
        raise VulnerabilityExceptionError(
            f"invalid vulnerability exception {spec!r}: {version_spec!r} is not a valid PEP 440 "
            "version specifier"
        ) from exc

    return VulnerabilityException(
        id=vuln_id,
        package=canonicalize_name(package),
        versions=versions,
        expires=expires,
        reason=reason,
    )


def parse_vulnerability_exceptions(specs: Iterable[str]) -> list[VulnerabilityException]:
    """
    Parse vulnerability exception specifications, preserving their order.
    """
    return [parse_vulnerability_exception(spec) for spec in specs]


def find_matching_exception(
    exceptions: Iterable[VulnerabilityException],
    dep: Dependency,
    vuln: VulnerabilityResult,
    now: date | None = None,
) -> VulnerabilityException | None:
    """
    Return the first exception that suppresses `vuln` for `dep`, or `None` if
    none of the exceptions match.
    """
    for exception in exceptions:
        if exception.matches(dep, vuln, now=now):
            return exception
    return None
