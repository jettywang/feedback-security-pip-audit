import sys

import pytest

import pip_audit._format as format
from pip_audit._format.columns import _osc8_link
from pip_audit._format.interface import pypi_url, vuln_id_url


# Shortcuts for building expected output with OSC8 links
def _P(name):
    return _osc8_link(name, pypi_url(name))


def _V(vid):
    return _osc8_link(vid, vuln_id_url(vid))


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_columns_not_manifest(output_desc, output_aliases):
    fmt = format.ColumnsFormat(output_desc, output_aliases)
    assert not fmt.is_manifest


def test_columns(vuln_data):
    columns_format = format.ColumnsFormat(True, True)
    expected_columns = """Name Version ID     Fix Versions Aliases        Description
---- ------- ------ ------------ -------------- ------------------------
foo  1.0     VULN-0 1.1,1.4      CVE-0000-00000 The first vulnerability
foo  1.0     VULN-1 1.0          CVE-0000-00001 The second vulnerability
bar  0.1     VULN-2              CVE-0000-00002 The third vulnerability"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_no_desc(vuln_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Version ID     Fix Versions Aliases
---- ------- ------ ------------ --------------
foo  1.0     VULN-0 1.1,1.4      CVE-0000-00000
foo  1.0     VULN-1 1.0          CVE-0000-00001
bar  0.1     VULN-2              CVE-0000-00002"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_no_desc_no_aliases(vuln_data):
    columns_format = format.ColumnsFormat(False, False)
    expected_columns = """Name Version ID     Fix Versions
---- ------- ------ ------------
foo  1.0     VULN-0 1.1,1.4
foo  1.0     VULN-1 1.0
bar  0.1     VULN-2"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_skipped_dep(vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Version ID     Fix Versions Aliases
---- ------- ------ ------------ --------------
foo  1.0     VULN-0 1.1,1.4      CVE-0000-00000

Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(vuln_data_skipped_dep, []) == expected_columns


def test_columns_no_vuln_data(no_vuln_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = ""
    assert columns_format.format(no_vuln_data, []) == expected_columns


def test_column_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(no_vuln_data_skipped_dep, []) == expected_columns


def test_columns_fix(vuln_data, fix_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Version ID     Fix Versions Applied Fix                            Aliases
---- ------- ------ ------------ -------------------------------------- --------------
foo  1.0     VULN-0 1.1,1.4      Successfully upgraded foo (1.0 => 1.8) CVE-0000-00000
foo  1.0     VULN-1 1.0          Successfully upgraded foo (1.0 => 1.8) CVE-0000-00001
bar  0.1     VULN-2              Successfully upgraded bar (0.1 => 0.3) CVE-0000-00002"""
    assert columns_format.format(vuln_data, fix_data) == expected_columns


def test_columns_skipped_fix(vuln_data, skipped_fix_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Version ID     Fix Versions Applied Fix                            Aliases
---- ------- ------ ------------ -------------------------------------- --------------
foo  1.0     VULN-0 1.1,1.4      Successfully upgraded foo (1.0 => 1.8) CVE-0000-00000
foo  1.0     VULN-1 1.0          Successfully upgraded foo (1.0 => 1.8) CVE-0000-00001
bar  0.1     VULN-2              Failed to fix bar (0.1): skip-reason   CVE-0000-00002"""
    assert columns_format.format(vuln_data, skipped_fix_data) == expected_columns


def test_columns_terminal_links(monkeypatch, vuln_data):
    monkeypatch.setattr(sys, "stdout", type("FakeTTY", (), {"isatty": lambda self: True})())
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = f"""Name Version ID     Fix Versions Aliases
---- ------- ------ ------------ --------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      {_V("CVE-0000-00000")}
{_P("foo")}  1.0     {_V("VULN-1")} 1.0          {_V("CVE-0000-00001")}
{_P("bar")}  0.1     {_V("VULN-2")}              {_V("CVE-0000-00002")}"""
    assert columns_format.format(vuln_data, []) == expected_columns


def _ignored_vuln_data():
    from packaging.version import Version

    import pip_audit._service as service

    dep = service.ResolvedDependency(name="foo", version=Version("1.0"))
    active = service.VulnerabilityResult(
        id="VULN-0",
        description="The first vulnerability",
        fix_versions=[Version("1.1")],
        aliases=set(),
    )
    suppressed = service.VulnerabilityResult(
        id="VULN-1",
        description="The second vulnerability",
        fix_versions=[],
        aliases={"CVE-2024-0001"},
        ignored_reason="approved until month end "
        "(exception for CVE-2024-0001 on foo ==1.0, expires 2026-11-30)",
    )
    return {dep: [active, suppressed]}


def test_columns_exception_reason_column():
    columns_format = format.ColumnsFormat(False, False)
    rendered = columns_format.format(_ignored_vuln_data(), [])
    lines = rendered.splitlines()
    assert "Exception Reason" in lines[0]
    assert "approved until month end" in rendered
    # The active vulnerability has an empty reason cell.
    assert "VULN-0" in rendered


def test_columns_no_exception_reason_column_without_suppressions(vuln_data):
    columns_format = format.ColumnsFormat(False, False)
    assert "Exception Reason" not in columns_format.format(vuln_data, [])
