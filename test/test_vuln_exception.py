from datetime import date

import pytest
from packaging.version import Version

from pip_audit._service.interface import (
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
)
from pip_audit._vuln_exception import (
    VulnerabilityExceptionError,
    find_matching_exception,
    parse_vulnerability_exception,
    parse_vulnerability_exceptions,
)

CVE = "CVE-2024-0001"


def _dep(name: str, version: str) -> ResolvedDependency:
    return ResolvedDependency(name=name, version=Version(version))


def _vuln(vuln_id: str = "PYSEC-1", aliases: set[str] | None = None) -> VulnerabilityResult:
    return VulnerabilityResult(
        id=vuln_id,
        description="a vulnerability",
        fix_versions=[Version("2.0")],
        aliases=aliases if aliases is not None else {CVE},
    )


class TestParse:
    def test_full_spec(self):
        exception = parse_vulnerability_exception(
            f"{CVE}:Some-Package:>=1.0,<2.0:2026-11-30:approved until month end"
        )
        assert exception.id == CVE
        assert exception.package == "some-package"
        assert str(exception.versions) == "<2.0,>=1.0"
        assert exception.expires == date(2026, 11, 30)
        assert exception.reason == "approved until month end"

    def test_minimal_spec_has_no_expiry_or_reason(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:==1.0.0")
        assert exception.id == CVE
        assert exception.package == "foo"
        assert exception.expires is None
        assert exception.reason is None

    def test_reason_may_contain_colons(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:==1.0.0:2026-11-30:see: ticket: 42")
        assert exception.reason == "see: ticket: 42"

    def test_blank_expiration_is_treated_as_missing(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:==1.0.0::no expiry reason")
        assert exception.expires is None
        assert exception.reason == "no expiry reason"

    def test_whitespace_is_trimmed(self):
        exception = parse_vulnerability_exception(f"  {CVE} : Foo-Bar : >=1.0 : : ")
        assert exception.package == "foo-bar"
        assert exception.reason is None

    def test_parse_many_preserves_order(self):
        exceptions = parse_vulnerability_exceptions(
            [f"{CVE}:foo:==1.0.0", "CVE-2024-0002:bar:>=2.0"]
        )
        assert [exception.id for exception in exceptions] == [CVE, "CVE-2024-0002"]

    @pytest.mark.parametrize(
        "spec",
        [
            "CVE-2024-0001",
            "CVE-2024-0001:foo",
            ":foo:==1.0.0",
            "CVE-2024-0001::==1.0.0",
            "CVE-2024-0001:foo:",
        ],
    )
    def test_invalid_spec_raises(self, spec):
        with pytest.raises(VulnerabilityExceptionError):
            parse_vulnerability_exception(spec)

    def test_invalid_date_raises(self):
        with pytest.raises(VulnerabilityExceptionError):
            parse_vulnerability_exception(f"{CVE}:foo:==1.0.0:not-a-date")

    def test_invalid_version_spec_raises(self):
        with pytest.raises(VulnerabilityExceptionError):
            parse_vulnerability_exception(f"{CVE}:foo:not-a-spec")


class TestMatching:
    @pytest.fixture
    def exception(self):
        return parse_vulnerability_exception(f"{CVE}:some-pkg:>=1.0,<2.0:2026-11-30")

    def test_matches_alias_case_insensitively(self, exception):
        vuln = _vuln(vuln_id="pysec-1", aliases={"ghsa-aaaa", "cve-2024-0001"})
        assert exception.matches(_dep("Some_Pkg", "1.5"), vuln, now=date(2026, 11, 12))

    def test_matches_primary_id(self):
        exception = parse_vulnerability_exception("PYSEC-1:foo:==1.0.0")
        assert exception.matches(_dep("foo", "1.0.0"), _vuln(aliases=set()))

    def test_does_not_match_other_package(self, exception):
        assert not exception.matches(_dep("other-pkg", "1.5"), _vuln(), now=date(2026, 11, 12))

    def test_does_not_match_version_outside_range(self, exception):
        assert not exception.matches(_dep("some-pkg", "2.0"), _vuln(), now=date(2026, 11, 12))

    def test_does_not_match_unrelated_vulnerability(self, exception):
        vuln = _vuln(vuln_id="PYSEC-2", aliases={"CVE-2024-9999"})
        assert not exception.matches(_dep("some-pkg", "1.5"), vuln, now=date(2026, 11, 12))

    def test_does_not_match_skipped_dependency(self, exception):
        skipped = SkippedDependency(name="some-pkg", skip_reason="reason")
        assert not exception.matches(skipped, _vuln(), now=date(2026, 11, 12))

    def test_valid_on_expiration_day(self, exception):
        assert exception.matches(_dep("some-pkg", "1.0"), _vuln(), now=date(2026, 11, 30))

    def test_expired_one_day_later_does_not_match(self, exception):
        assert not exception.matches(_dep("some-pkg", "1.0"), _vuln(), now=date(2026, 12, 1))

    def test_no_expiry_always_matches(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:==1.0.0")
        assert exception.matches(_dep("foo", "1.0.0"), _vuln(), now=date(2099, 1, 1))

    def test_find_matching_returns_first_match_and_none_otherwise(self, exception):
        dep = _dep("some-pkg", "1.0")
        vuln = _vuln()
        assert find_matching_exception([exception], dep, vuln, now=date(2026, 11, 12)) is exception
        assert find_matching_exception([exception], dep, vuln, now=date(2026, 12, 1)) is None


class TestRenderReason:
    def test_reason_with_user_justification(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:>=1.0,<2.0:2026-11-30:risk accepted")
        rendered = exception.render_reason()
        assert rendered.startswith("risk accepted (")
        assert CVE in rendered
        assert "foo" in rendered
        assert "2026-11-30" in rendered

    def test_reason_without_user_justification(self):
        exception = parse_vulnerability_exception(f"{CVE}:foo:==1.0.0")
        rendered = exception.render_reason()
        assert rendered == f"Exception for {CVE} on foo ==1.0.0"
