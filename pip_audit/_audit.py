"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

from pip_audit._dependency_source import DependencySource
from pip_audit._merge import merge_vulnerability_results
from pip_audit._service import Dependency, VulnerabilityResult, VulnerabilityService

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool = False


class Auditor:
    """
    The core class of the `pip-audit` API.

    For a given dependency source and vulnerability service, supply a mapping of dependencies to
    known vulnerabilities.
    """

    def __init__(
        self,
        service: VulnerabilityService,
        options: AuditOptions = AuditOptions(),
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        self._service = service
        self._options = options

    def audit(
        self, source: DependencySource
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Perform the auditing step, collecting dependencies from `source`.

        Individual vulnerability results are uniqued based on their `aliases`
        sets: any two results for the same dependency that share an identifier
        (transitively, via aliases) are collapsed into a single result. The
        merged result keeps the union of all aliases, the actionable fix
        versions from every still-active record, and per-source evidence
        describing what each service reported.

        The merge is order-independent: reordering the service results does
        not change the output. Results whose underlying records have all been
        withdrawn are dropped; a result stays reported as long as any source
        still considers it active.
        """
        specs = source.collect()

        if self._options.dry_run:
            # Drain the iterator in dry-run mode.
            logger.info(f"Dry run: would have audited {len(list(specs))} packages")
            yield from ()
        else:
            for dep, vulns in self._service.query_all(specs):
                yield dep, merge_vulnerability_results(vulns)
