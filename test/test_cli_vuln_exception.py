import datetime
import os

import pretend
import pytest
from packaging.version import Version

import pip_audit._cli
from pip_audit._service.interface import ResolvedDependency, VulnerabilityResult

CVE = "CVE-2024-0001"
EXCEPTION = f"{CVE}:some-pkg:==1.0.0:2026-11-30:approved until month end"


def _dep(name, version):
    return ResolvedDependency(name=name, version=Version(version))


def _vuln():
    return VulnerabilityResult(
        id="PYSEC-1",
        description="a vulnerability",
        fix_versions=[Version("2.0.0")],
        aliases={CVE},
    )


def _run_cli(monkeypatch, capsys, args, result, today=None):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    args = ["--progress-spinner", "off", "--cache-dir", os.environ["TMPDIR"], *args]
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    if today is not None:

        class FakeDate(datetime.date):
            @classmethod
            def today(cls):
                return today

        monkeypatch.setattr(pip_audit._vuln_exception, "date", FakeDate)

    exit_code = 0
    try:
        pip_audit._cli.audit()
    except SystemExit as exc:
        exit_code = exc.code if exc.code is not None else 0

    captured = capsys.readouterr()
    return exit_code, captured.err, captured.out


@pytest.fixture
def two_packages():
    # The same CVE affects two packages, one of them at two versions.
    return [
        (_dep("some-pkg", "1.0.0"), [_vuln()]),
        (_dep("some-pkg", "1.5.0"), [_vuln()]),
        (_dep("other-pkg", "1.0.0"), [_vuln()]),
    ]


def test_exception_suppresses_only_scoped_hits(monkeypatch, capsys, two_packages):
    exit_code, err, out = _run_cli(
        monkeypatch,
        capsys,
        ["--vuln-exception", EXCEPTION],
        two_packages,
        today=datetime.date(2026, 11, 12),
    )

    assert "Found 2 known vulnerabilities, ignored 1 in 2 packages" in err
    assert "approved until month end" in out
    assert CVE in out
    # The two unaffected reports remain ordinary vulnerabilities.
    assert "1.5.0" in out
    assert "other-pkg" in out
    assert exit_code == 1


def test_exception_keeps_report_with_zero_exit_code(monkeypatch, capsys):
    result = [(_dep("some-pkg", "1.0.0"), [_vuln()])]
    exit_code, err, out = _run_cli(
        monkeypatch,
        capsys,
        ["--vuln-exception", EXCEPTION],
        result,
        today=datetime.date(2026, 11, 12),
    )

    assert "No known vulnerabilities found, 1 ignored" in err
    assert "approved until month end" in out
    assert exit_code == 0


def test_expired_exception_is_ignored(monkeypatch, capsys):
    result = [(_dep("some-pkg", "1.0.0"), [_vuln()])]
    exit_code, err, out = _run_cli(
        monkeypatch,
        capsys,
        ["--vuln-exception", EXCEPTION],
        result,
        today=datetime.date(2026, 12, 1),
    )

    assert "Found 1 known vulnerability in 1 package" in err
    assert "approved until month end" not in out
    assert exit_code == 1


def test_exception_matches_alias_and_coexists_with_ignore_vuln(monkeypatch, capsys):
    broad_vuln = VulnerabilityResult(
        id="PYSEC-9",
        description="another vulnerability",
        fix_versions=[],
        aliases={"CVE-2024-9999"},
    )
    result = [(_dep("some-pkg", "1.0.0"), [_vuln(), broad_vuln])]
    exit_code, err, out = _run_cli(
        monkeypatch,
        capsys,
        [
            "--vuln-exception",
            EXCEPTION,
            "--ignore-vuln",
            "CVE-2024-9999",
        ],
        result,
        today=datetime.date(2026, 11, 12),
    )

    assert "No known vulnerabilities found, 2 ignored" in err
    assert "approved until month end" in out
    assert exit_code == 0


def test_invalid_exception_spec_fails(monkeypatch):
    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(
            [
                "--progress-spinner",
                "off",
                "--cache-dir",
                os.environ["TMPDIR"],
                "--vuln-exception",
                "not-enough-fields",
            ]
        ),
    )

    with pytest.raises(SystemExit) as exc_info:
        pip_audit._cli.audit()
    assert exc_info.value.code == 2
