"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, NewType

from packaging.utils import canonicalize_name
from packaging.version import Version

VulnerabilityID = NewType("VulnerabilityID", str)


def _id_comparison_key(id: str) -> int:
    if id.startswith("PYSEC"):
        return 1
    elif id.startswith("CVE"):
        return 2
    return 3


@dataclass(frozen=True)
class VulnerabilityEvidence:
    """
    A single piece of evidence for a vulnerability, as reported by one
    vulnerability service for one package version.

    Multiple `VulnerabilityEvidence` entries are attached to a merged
    `VulnerabilityResult` when more than one service (or more than one
    identifier) reports the same underlying vulnerability.
    """

    id: VulnerabilityID
    """
    The identifier the service used for this piece of evidence.
    """

    source: str
    """
    The vulnerability service that produced this piece of evidence.
    """

    description: str
    """
    The service-provided description for the vulnerability.
    """

    fix_versions: tuple[Version, ...]
    """
    The versions reported by the service as resolving the vulnerability.
    An empty tuple means the service did not provide a fix version.
    """

    aliases: frozenset[VulnerabilityID] = frozenset()
    """
    The alternative identifiers reported alongside this piece of evidence.
    """

    withdrawn: str | None = None
    """
    The service-provided withdrawal timestamp, or `None` if the record is
    still active.
    """

    @property
    def is_withdrawn(self) -> bool:
        """
        Whether this piece of evidence comes from a withdrawn record.
        """
        return self.withdrawn is not None


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

    source: str = "unknown"
    """
    The vulnerability service that produced this result.
    """

    withdrawn: str | None = None
    """
    The service-provided withdrawal timestamp, or `None` if this result is
    still active.
    """

    evidence: tuple[VulnerabilityEvidence, ...] = ()
    """
    The per-source evidence backing this result. This always contains at
    least one entry for a result produced by a service, and accumulates one
    entry per merged record when aliases are collapsed together.
    """

    @property
    def is_withdrawn(self) -> bool:
        """
        Whether every piece of evidence for this result has been withdrawn.

        A result is only treated as withdrawn when *all* of its sources have
        withdrawn their records: a single active record keeps the result
        reported, with the withdrawn records retained as evidence.
        """
        return bool(self.evidence) and all(e.is_withdrawn for e in self.evidence)

    @classmethod
    def create(
        cls,
        ids: list[VulnerabilityID],
        description: str,
        fix_versions: list[Version],
        published: datetime | None,
        source: str = "unknown",
        withdrawn: str | None = None,
    ) -> VulnerabilityResult:
        """
        Instantiates a `VulnerabilityResult` with the given data, prioritizing
        PYSEC and CVE vulnerability IDs for the primary identifier.
        """

        ids.sort(key=_id_comparison_key)
        primary = ids[0]
        aliases = set(ids[1:])
        evidence = (
            VulnerabilityEvidence(
                id=primary,
                source=source,
                description=description,
                fix_versions=tuple(fix_versions),
                aliases=frozenset(aliases),
                withdrawn=withdrawn,
            ),
        )
        return cls(
            id=primary,
            description=description,
            fix_versions=fix_versions,
            aliases=aliases,
            published=published,
            source=source,
            withdrawn=withdrawn,
            evidence=evidence,
        )

    def all_ids(self) -> set[VulnerabilityID]:
        """
        Return every identifier known for this result: its primary ID and
        all of its aliases.
        """
        return self.aliases | {self.id}

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
        """
        for spec in specs:
            yield self.query(spec)

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
