"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Any, NewType

from packaging.utils import canonicalize_name
from packaging.version import Version

VulnerabilityID = NewType("VulnerabilityID", str)


class AuditStatus(Enum):
    """
    The outcome of attempting to audit a single dependency.

    This distinguishes a dependency that was *successfully queried and has no
    vulnerabilities from one that could not be given a valid query result
    (because it was unknown to the service or the query failed). Both can end up
    next to an empty vulnerability list, so the empty list alone is ambiguous.
    """

    Success = "success"
    """
    The service returned a valid response for the dependency. An accompanying
    empty vulnerability list means "queried and found no vulnerabilities".
    """

    NotKnown = "not_known"
    """
    The service explicitly reported the dependency/version as unknown (e.g. an
    HTTP 404 from PyPI). No vulnerability result is available.
    """

    Error = "error"
    """
    The query could not be completed (rate limiting, server error, timeout,
    malformed response, ...). No vulnerability result is available.
    """

    @property
    def has_valid_result(self) -> bool:
        """
        Whether the dependency received a valid, trustworthy query result.
        """
        return self is AuditStatus.Success


def _id_comparison_key(id: str) -> int:
    if id.startswith("PYSEC"):
        return 1
    elif id.startswith("CVE"):
        return 2
    return 3


@dataclass(frozen=True)
class Dependency:
    """
    Represents an abstract Python package.

    This class cannot be constructed directly.
    """

    name: str
    """
    The package's **uncanonicalized** name.

    Use the `canonicalized_name` property when a canonicalized form is necessary.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        """
        A stub constructor that always fails.
        """
        raise NotImplementedError

    # TODO(ww): Use functools.cached_property when supported Python is 3.8+.
    @property
    def canonical_name(self) -> str:
        """
        The `Dependency`'s PEP-503 canonicalized name.
        """
        return canonicalize_name(self.name)

    def is_skipped(self) -> bool:
        """
        Check whether the `Dependency` was skipped by the audit.
        """
        return self.__class__ is SkippedDependency

    @property
    def audit_status(self) -> AuditStatus:
        """
        The outcome of auditing this dependency.

        A resolved (non-skipped) dependency was successfully queried, so its
        status is always `AuditStatus.Success`; skipped dependencies carry an
        explicit non-success status.
        """
        return AuditStatus.Success


@dataclass(frozen=True)
class ResolvedDependency(Dependency):
    """
    Represents a fully resolved Python package.
    """

    version: Version


@dataclass(frozen=True)
class SkippedDependency(Dependency):
    """
    Represents a Python package that was unable to be audited and therefore, skipped.
    """

    skip_reason: str
    audit_status: AuditStatus = AuditStatus.NotKnown


@dataclass(frozen=True)
class VulnerabilityResult:
    """
    Represents a "result" from a vulnerability service, indicating a vulnerability
    in some Python package.
    """

    id: VulnerabilityID
    """
    A service-provided identifier for the vulnerability.
    """

    description: str
    """
    A human-readable description of the vulnerability.
    """

    fix_versions: list[Version]
    """
    A list of versions that can be upgraded to that resolve the vulnerability.
    """

    aliases: set[VulnerabilityID]
    """
    A set of aliases (alternative identifiers) for this result.
    """

    published: datetime | None = None
    """
    When the vulnerability was first published.
    """

    @classmethod
    def create(
        cls,
        ids: list[VulnerabilityID],
        description: str,
        fix_versions: list[Version],
        published: datetime | None,
    ) -> VulnerabilityResult:
        """
        Instantiates a `VulnerabilityResult` with the given data, prioritizing
        PYSEC and CVE vulnerability IDs for the primary identifier.
        """

        ids.sort(key=_id_comparison_key)
        return cls(ids[0], description, fix_versions, set(ids[1:]), published)

    def alias_of(self, other: VulnerabilityResult) -> bool:
        """
        Returns whether this result is an "alias" of another result.

        Two results are said to be aliases if their respective sets of
        `{id, *aliases}` intersect at all. A result is therefore its own alias.
        """
        return bool((self.aliases | {self.id}).intersection(other.aliases | {other.id}))

    def merge_aliases(self, other: VulnerabilityResult) -> VulnerabilityResult:
        """
        Merge `other`'s aliases into this result, returning a new result.
        """

        # Our own ID should never occur in the alias set.
        aliases = self.aliases | other.aliases - {self.id}
        return replace(self, aliases=aliases)

    def has_any_id(self, ids: set[str]) -> bool:
        """
        Returns whether ids intersects with {id} | aliases.
        """
        return bool(ids & (self.aliases | {self.id}))


class VulnerabilityService(ABC):
    """
    Represents an abstract provider of Python package vulnerability information.
    """

    @abstractmethod
    def query(
        self, spec: Dependency
    ) -> tuple[Dependency, list[VulnerabilityResult]]:  # pragma: no cover
        """
        Query the `VulnerabilityService` for information about the given `Dependency`,
        returning a list of `VulnerabilityResult`.
        """
        raise NotImplementedError

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Query the vulnerability service for information on multiple dependencies.

        `VulnerabilityService` implementations can override this implementation with
        a more optimized one, if they support batched or bulk requests.

        A failure to query a single dependency is contained rather than allowed to
        abort the whole audit: the offending dependency is yielded as an
        `SkippedDependency` whose `audit_status` is `AuditStatus.Error`, so the
        formatted result can distinguish "queried and clean" from "never got a
        result". Dependencies that were already skipped are passed through untouched.
        """
        for spec in specs:
            try:
                yield self.query(spec)
            except ServiceError as e:
                if spec.is_skipped():
                    yield spec, []
                else:
                    skipped = SkippedDependency(
                        name=spec.name,
                        skip_reason=f"Failed to query vulnerability service: {e}",
                        audit_status=AuditStatus.Error,
                    )
                    yield skipped, []

    @staticmethod
    def _parse_rfc3339(dt: str | None) -> datetime | None:
        if dt is None:
            return None

        # NOTE: OSV's schema says timestamps are RFC3339 but strptime
        # has no way to indicate an optional field (like `%f`), so
        # we have to try-and-retry with the two different expected formats.
        # See: https://github.com/google/osv.dev/issues/857
        try:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ")


class ServiceError(Exception):
    """
    Raised when a `VulnerabilityService` fails, for any reason.

    Concrete implementations of `VulnerabilityService` are expected to subclass
    this exception to provide more context.
    """

    pass


class ConnectionError(ServiceError):
    """
    A specialization of `ServiceError` specifically for cases where the
    vulnerability service is unreachable or offline.
    """

    pass
