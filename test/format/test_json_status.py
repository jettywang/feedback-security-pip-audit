"""The JSON manifest must make per-package query status unambiguous."""

import json

from packaging.version import Version

import pip_audit._format as format
import pip_audit._service as service


def test_json_distinguishes_clean_not_known_and_error():
    clean = service.ResolvedDependency(name="clean", version=Version("1.0.0"))
    unknown = service.SkippedDependency(
        name="ghost",
        skip_reason="Dependency not found on PyPI and could not be audited: ghost (9.9.9)",
        audit_status=service.AuditStatus.NotKnown,
    )
    failed = service.SkippedDependency(
        name="rate-limited",
        skip_reason="Failed to query vulnerability service: ",
        audit_status=service.AuditStatus.Error,
    )

    result = {clean: [], unknown: [], failed: []}
    rendered = json.loads(format.JsonFormat(False, False).format(result, []))

    deps = {d["name"]: d for d in rendered["dependencies"]}

    # Clean package: empty vulns but an explicit successful status.
    assert deps["clean"] == {
        "name": "clean",
        "version": "1.0.0",
        "audit_status": "success",
        "has_vulnerability_result": True,
        "vulns": [],
    }

    # Unknown package: no result, distinct from a clean package.
    assert deps["ghost"]["audit_status"] == "not_known"
    assert deps["ghost"]["has_vulnerability_result"] is False
    assert "skip_reason" in deps["ghost"]
    assert "vulns" not in deps["ghost"]

    # Failed package: no result, flagged as an error rather than not-known.
    assert deps["rate-limited"]["audit_status"] == "error"
    assert deps["rate-limited"]["has_vulnerability_result"] is False

    assert rendered["coverage"] == {
        "total": 3,
        "valid_query_result": 1,
        "not_known": 1,
        "error": 1,
        "complete": False,
    }


def test_json_coverage_complete_when_all_succeed():
    a = service.ResolvedDependency(name="a", version=Version("1.0.0"))
    b = service.ResolvedDependency(name="b", version=Version("2.0.0"))
    rendered = json.loads(
        format.JsonFormat(False, False).format({a: [], b: []}, [])
    )
    assert rendered["coverage"] == {
        "total": 2,
        "valid_query_result": 2,
        "not_known": 0,
        "error": 0,
        "complete": True,
    }
    assert all(d["audit_status"] == "success" for d in rendered["dependencies"])
