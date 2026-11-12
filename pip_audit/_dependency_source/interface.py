"""
Interfaces for interacting with "dependency sources", i.e. sources
of fully resolved Python dependency trees.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from pip_audit._fix import Constraints, ResolvedFixVersion
from pip_audit._service import Dependency

PYPI_URL = "https://pypi.org/simple/"


class DependencySource(ABC):
    """
    Represents an abstract source of fully-resolved Python dependencies.

    Individual concrete dependency sources (e.g. `pip list`) are expected
    to subclass `DependencySource` and implement it in their terms.
    """

    @abstractmethod
    def collect(self) -> Iterator[Dependency]:  # pragma: no cover
        """
        Yield the dependencies in this source.
        """
        raise NotImplementedError

    @abstractmethod
    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Upgrade a dependency to the given fix version.
        """
        raise NotImplementedError

    def get_constraints(self) -> Constraints:
        """
        Return the version constraints this source imposes on each package.

        These constraints are used to ensure that `--fix` only selects upgrade candidates that
        remain installable from the source. Sources without explicit version constraints (for
        example, an already-installed environment audited via `pip`) return an empty mapping.
        """
        return {}


class DependencySourceError(Exception):
    """
    Raised when a `DependencySource` fails to provide its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass


class DependencyFixError(Exception):
    """
    Raised when a `DependencySource` fails to perform a "fix" operation, i.e.
    fails to upgrade a package to a different version.

    Concrete implementations are expected to subclass this exception to provide
    more context.
    """

    pass


class InvalidRequirementSpecifier(DependencySourceError):
    """
    A `DependencySourceError` specialized for the case of a non-PEP 440 requirements
    specifier.
    """

    pass
