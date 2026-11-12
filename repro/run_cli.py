"""
Replay pip-audit's exact CLI audit loop against scripted multi-package services
to observe real exit codes and the emitted JSON when a mid-run package fails.

Mirrors pip_audit/_cli.py: the per-package loop, the skipped/error handling,
vuln_count gating, manifest output, and sys.exit points.
"""

from __future__ import annotations

import io
import json as _json
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402
from packaging.version import Version  # noqa: E402

import pip_audit._service as service  # noqa: E402
from pip_audit._audit import Auditor, AuditOptions  # noqa: E402
from pip_audit._dependency_source.interface import (  # noqa: E402
    DependencySource,
    DependencySourceError,
)
from pip_audit._format.json import JsonFormat  # noqa: E402
from pip_audit._service.interface import (  # noqa: E402
    ConnectionError as VulnServiceConnectionError,
)


class ListSource(DependencySource):
    def __init__(self, deps):
        self._deps = deps

    def collect(self):
        return iter(self._deps)

    def fix(self, _):
        raise NotImplementedError


def cli_audit(pypi, deps, strict=False, formatter=None):
    """Faithful re-implementation of the _cli.py audit + output/exit block."""
    formatter = formatter or JsonFormat(False, False)
    auditor = Auditor(pypi, AuditOptions(dry_run=False))
    source = ListSource(deps)

    result = {}
    pkg_count = vuln_count = skip_count = 0
    exit_code = 0
    fatal = None
    err = io.StringIO()
    with redirect_stderr(err):
        try:
            for spec, vulns in auditor.audit(source):
                if spec.is_skipped():
                    if strict:
                        fatal = f"{spec.name}: {spec.skip_reason}"
                        exit_code = 1
                        break
                    skip_count += 1
                result[spec] = vulns
                if len(vulns) > 0:
                    pkg_count += 1
                    vuln_count += len(vulns)
        except DependencySourceError as e:
            fatal, exit_code = str(e), 1
        except VulnServiceConnectionError as e:
            fatal = "Tip: your network may be blocking this service. Try -s SERVICE"
            exit_code = 1
        except service.ServiceError as e:
            # With per-package containment this should no longer be reachable via
            # query_all; kept to mirror the real _cli.py defensive structure.
            fatal, exit_code = f"UNCAUGHT ServiceError: {e}", 1

    # Output block mirrors _cli.py: manifest formats print whenever skips/manifest
    emitted = None
    if exit_code == 0 and (vuln_count > 0 or skip_count > 0 or formatter.is_manifest):
        emitted = formatter.format(result, [])
    return {
        "exit_code": exit_code,
        "fatal": fatal,
        "stderr": err.getvalue().strip(),
        "json": _json.loads(emitted) if emitted else None,
        "result_deps": [
            (d.canonical_name, ("SKIP:" + d.skip_reason) if d.is_skipped() else f"{len(v)} vulns")
            for d, v in result.items()
        ],
    }


def pypi_url(name, version):
    canon = service.ResolvedDependency(name, Version(version)).canonical_name
    return f"https://pypi.org/pypi/{canon}/{version}/json"


def h(clock, **extra):
    base = {"Date": harness.http_date(clock), "Content-Type": "application/json", **extra}
    return base


def main():
    deps = [
        service.ResolvedDependency("alpha", Version("1.0.0")),
        service.ResolvedDependency("beta", Version("2.0.0")),
        service.ResolvedDependency("gamma", Version("3.0.0")),
    ]
    urls = {d.name: pypi_url(d.name, str(d.version)) for d in deps}

    def build(routes, start=7_000_000.0):
        clock = harness.FakeClock(start)
        td = tempfile.mkdtemp()
        sess, responder = harness.make_session(Path(td), clock, routes)
        pypi = service.PyPIService(Path(td))
        pypi.session = sess
        return pypi, responder, clock

    def title(t):
        print("\n" + "#" * 78 + f"\n# {t}\n" + "#" * 78)

    # A: all healthy & clean -> all empty vuln lists
    title("A. all 200 clean (all packages queried, zero vulns)")
    clock_a = harness.FakeClock(7_000_000.0)
    routes = {u: [(200, h(clock_a), harness.json_body({"vulnerabilities": []}))]
              for u in urls.values()}
    pypi, resp, _ = build(routes)
    print(_json.dumps(cli_audit(pypi, deps), indent=2))
    print("network hits:", resp.network_hits())

    # B: middle package 404 (skipped), others clean
    title("B. beta -> 404 (skipped); alpha/gamma clean")
    clock = harness.FakeClock(8_000_000.0)
    routes = {}
    for name, u in urls.items():
        if name == "beta":
            routes[u] = [(404, {"Date": harness.http_date(clock)}, b"x")]
        else:
            routes[u] = [(200, h(clock), harness.json_body({"vulnerabilities": []}))]
    pypi, resp, _ = build(routes, start=8_000_000.0)
    print(_json.dumps(cli_audit(pypi, deps), indent=2))

    # C: middle package 500 (server error) -> aborts run
    title("C. beta -> 500 (server error mid-run)")
    clock = harness.FakeClock(9_000_000.0)
    routes = {}
    for name, u in urls.items():
        if name == "beta":
            routes[u] = [(500, {"Date": harness.http_date(clock)}, b"boom")]
        else:
            routes[u] = [(200, h(clock), harness.json_body({"vulnerabilities": []}))]
    pypi, resp, _ = build(routes, start=9_000_000.0)
    out = cli_audit(pypi, deps)
    print(_json.dumps(out, indent=2))
    print("network hits (alpha done, beta failed; gamma never reached):", resp.network_hits())

    # D: middle package 429 (rate limit) -> aborts run
    title("D. beta -> 429 (rate limited mid-run)")
    clock = harness.FakeClock(10_000_000.0)
    routes = {}
    for name, u in urls.items():
        if name == "beta":
            routes[u] = [(429, {"Date": harness.http_date(clock), "Retry-After": "60"}, b"slow")]
        else:
            routes[u] = [(200, h(clock), harness.json_body({"vulnerabilities": []}))]
    pypi, resp, _ = build(routes, start=10_000_000.0)
    print(_json.dumps(cli_audit(pypi, deps), indent=2))
    print("network hits:", resp.network_hits())


if __name__ == "__main__":
    main()
