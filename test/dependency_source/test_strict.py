from __future__ import annotations

from pathlib import Path

import pytest
from packaging.version import Version

import pip_audit._subprocess
import pip_audit._virtual_env
from pip_audit._audit import Auditor
from pip_audit._dependency_source import DependencyFixError
from pip_audit._dependency_source.strict import StrictRequirementSource
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityService,
)


@pytest.fixture(autouse=True)
def no_subprocess(monkeypatch):
    """
    A subprocess stand-in: any attempt to install or build anything (which the
    strict read-only source must never do) fails the test immediately.
    """

    def _fail(*args, **kwargs):
        raise AssertionError(f"read-only audit attempted to run a subprocess: {args}")

    monkeypatch.setattr(pip_audit._subprocess, "run", _fail)
    monkeypatch.setattr(pip_audit._subprocess, "Popen", _fail)
    monkeypatch.setattr(pip_audit._virtual_env, "run", _fail)


class RecordingService(VulnerabilityService):
    """
    A fake vulnerability service that records every dependency it looks up
    and reports no vulnerabilities.

    Like the real services, skipped dependencies are passed through without
    being looked up.
    """

    def __init__(self) -> None:
        self.queries: list[Dependency] = []

    def query(self, spec):
        if spec.is_skipped():
            return spec, []
        self.queries.append(spec)
        return spec, []


def _write(directory: Path, name: str, contents: str) -> Path:
    path = directory / name
    path.write_text(contents)
    return path


def _resolved(specs):
    return [s for s in specs if isinstance(s, ResolvedDependency)]


def _skipped(specs):
    return [s for s in specs if isinstance(s, SkippedDependency)]


def test_strict_collects_pinned(tmp_path):
    req = _write(tmp_path, "requirements.txt", "flask==2.0.1\nrequests==2.8.1\n")
    specs = list(StrictRequirementSource([req]).collect())

    assert _resolved(specs) == [
        ResolvedDependency("flask", Version("2.0.1")),
        ResolvedDependency("requests", Version("2.8.1")),
    ]
    assert _skipped(specs) == []


def test_strict_follows_local_includes(tmp_path):
    _write(tmp_path, "other.txt", "requests==2.8.1\n-r nested/more.txt\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    _write(nested, "more.txt", "packaging==21.0\n")
    req = _write(tmp_path, "requirements.txt", "flask==2.0.1\n-r other.txt\n")

    specs = list(StrictRequirementSource([req]).collect())

    assert _resolved(specs) == [
        ResolvedDependency("flask", Version("2.0.1")),
        ResolvedDependency("requests", Version("2.8.1")),
        ResolvedDependency("packaging", Version("21.0")),
    ]
    assert _skipped(specs) == []


def test_strict_include_cycle_terminates(tmp_path):
    _write(tmp_path, "b.txt", "bar==2.0\n-r a.txt\n")
    _write(tmp_path, "a.txt", "foo==1.0\n-r b.txt\n")

    specs = list(StrictRequirementSource([tmp_path / "a.txt"]).collect())

    assert _resolved(specs) == [
        ResolvedDependency("foo", Version("1.0")),
        ResolvedDependency("bar", Version("2.0")),
    ]


def test_strict_remote_include_skipped(tmp_path):
    req = _write(
        tmp_path,
        "requirements.txt",
        "flask==2.0.1\n-r https://example.com/remote-requirements.txt\n",
    )

    specs = list(StrictRequirementSource([req]).collect())

    assert _resolved(specs) == [ResolvedDependency("flask", Version("2.0.1"))]
    (skipped,) = _skipped(specs)
    assert "remote includes are not followed" in skipped.skip_reason


def test_strict_missing_include_skipped(tmp_path):
    req = _write(tmp_path, "requirements.txt", "flask==2.0.1\n-r missing.txt\n")

    specs = list(StrictRequirementSource([req]).collect())

    assert _resolved(specs) == [ResolvedDependency("flask", Version("2.0.1"))]
    (skipped,) = _skipped(specs)
    assert "does not exist" in skipped.skip_reason


def test_strict_applies_exact_constraints(tmp_path):
    _write(tmp_path, "constraints.txt", "flask==2.0.1\nrequests>=2.0\nunused==1.0\n")
    req = _write(tmp_path, "requirements.txt", "flask\nrequests\n-c constraints.txt\n")

    specs = list(StrictRequirementSource([req]).collect())

    # `flask` becomes auditable via its exact-pin constraint; `requests` only
    # has a range constraint and remains unauditable; `unused` constrains
    # nothing and is not itself a dependency.
    assert _resolved(specs) == [ResolvedDependency("flask", Version("2.0.1"))]
    (skipped,) = _skipped(specs)
    assert skipped.name == "requests"
    assert "not pinned to an exact version" in skipped.skip_reason


def test_strict_skips_unauditable_lines(tmp_path):
    req = _write(
        tmp_path,
        "requirements.txt",
        "\n".join(
            [
                "flask==2.0.1",
                "-e git+https://github.com/foo/editable.git#egg=editable",
                "git+https://github.com/foo/vcs.git#egg=vcs",
                "./local/sdist.tar.gz",
                "pkg @ https://example.com/pkg-1.0.tar.gz",
                "https://example.com/other-1.0.tar.gz",
                "unpinned>=1.0",
                "wildcard==1.0.*",
            ]
        ),
    )

    specs = list(StrictRequirementSource([req]).collect())

    # Only the exactly pinned requirement is auditable.
    assert _resolved(specs) == [ResolvedDependency("flask", Version("2.0.1"))]

    skipped = _skipped(specs)
    assert len(skipped) == 7
    reasons = {s.name: s.skip_reason for s in skipped}
    assert "editable" in reasons["editable"]
    assert "URL/VCS" in reasons["vcs"]
    assert "local file" in reasons["./local/sdist.tar.gz"]
    assert "URL/VCS" in reasons["pkg"]
    assert "URL/VCS" in reasons["https://example.com/other-1.0.tar.gz"]
    assert "not pinned to an exact version" in reasons["unpinned"]
    assert "not pinned to an exact version" in reasons["wildcard"]


def test_strict_marker_handling(tmp_path):
    req = _write(
        tmp_path,
        "requirements.txt",
        "included==1.0; python_version >= '3.0'\n"
        "excluded==2.0; python_version < '1.0'\n"
        "excluded-editable==3.0; python_version < '1.0'\n",
    )

    specs = list(StrictRequirementSource([req]).collect())

    # Marker-excluded lines are not part of the audited environment at all:
    # they are neither audited nor reported as skipped.
    assert _resolved(specs) == [ResolvedDependency("included", Version("1.0"))]
    assert _skipped(specs) == []


def test_strict_invalid_line_skipped(tmp_path):
    req = _write(tmp_path, "requirements.txt", "flask==2.0.1\na#b#c\n")

    specs = list(StrictRequirementSource([req]).collect())

    assert _resolved(specs) == [ResolvedDependency("flask", Version("2.0.1"))]
    (skipped,) = _skipped(specs)
    assert "invalid requirement" in skipped.skip_reason


def test_strict_conflicting_and_duplicate_pins(tmp_path):
    req = _write(
        tmp_path,
        "requirements.txt",
        "flask==2.0.1\nflask==2.0.1\nrequests==2.8.1\nrequests==2.9.0\n",
    )

    specs = list(StrictRequirementSource([req]).collect())

    # Identical duplicates are deduplicated; conflicting pins are skipped.
    assert _resolved(specs) == [
        ResolvedDependency("flask", Version("2.0.1")),
        ResolvedDependency("requests", Version("2.8.1")),
    ]
    (skipped,) = _skipped(specs)
    assert skipped.name == "requests"
    assert "conflicts with an earlier pin" in skipped.skip_reason


def test_strict_fix_is_unsupported(tmp_path):
    req = _write(tmp_path, "requirements.txt", "flask==2.0.1\n")
    source = StrictRequirementSource([req])

    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(ResolvedDependency("flask", Version("2.0.1")), Version("2.0.2"))
        )

    # The input is untouched.
    assert req.read_text() == "flask==2.0.1\n"


def test_strict_audit_only_queries_explicit_pins(tmp_path):
    _write(tmp_path, "constraints.txt", "constrained==3.1.4\n")
    req = _write(
        tmp_path,
        "requirements.txt",
        "\n".join(
            [
                "flask==2.0.1",
                "constrained",
                "-c constraints.txt",
                "-e git+https://github.com/foo/editable.git#egg=editable",
                "git+https://github.com/foo/vcs.git#egg=vcs",
                "./local/sdist.tar.gz",
                "unpinned>=1.0",
            ]
        ),
    )

    service = RecordingService()
    auditor = Auditor(service)
    results = dict(auditor.audit(StrictRequirementSource([req])))

    # Every dependency sent to the vulnerability service is resolved to an
    # explicit name and exact version: nothing was resolved, installed, or
    # built to get there (any subprocess use would have raised above).
    assert all(isinstance(q, ResolvedDependency) for q in service.queries)
    assert set(service.queries) == {
        ResolvedDependency("flask", Version("2.0.1")),
        ResolvedDependency("constrained", Version("3.1.4")),
    }

    # The remaining lines are reported as skipped, with reasons, and are never
    # sent to the vulnerability service.
    skipped = [d for d in results if isinstance(d, SkippedDependency)]
    assert len(skipped) == 4
    assert all(s.skip_reason for s in skipped)
