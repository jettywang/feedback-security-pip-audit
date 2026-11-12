"""
Reproduce pip-audit's behavior for each service-response condition using a fake
clock and scripted HTTP, against the real cache and service code.

Scenarios: valid (fresh) cache, stale/expired cache, 404, 429 (rate limit),
5xx. For each we report: whether an exception escapes (and thus what the CLI
exit code would be), the per-package (dependency, vulns) tuple, and how the JSON
formatter renders it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402
from packaging.version import Version  # noqa: E402

import pip_audit._service as service  # noqa: E402
from pip_audit._format.json import JsonFormat  # noqa: E402


def pypi_url(name: str, version: str) -> str:
    canon = service.ResolvedDependency(name, Version(version)).canonical_name
    return f"https://pypi.org/pypi/{canon}/{version}/json"


def make_pypi(cache_dir, clock, routes, monkeypatch_session=True):
    sess, responder = harness.make_session(cache_dir, clock, routes)
    pypi = service.PyPIService(cache_dir)
    pypi.session = sess  # inject the mock-backed caching session
    return pypi, responder


def classify(dep, vulns):
    if dep.is_skipped():
        return f"SKIPPED ({dep.skip_reason})"
    if vulns:
        return f"QUERIED, {len(vulns)} vuln(s)"
    return "QUERIED, empty vuln list (no vulns)"


def run_query(pypi, dep):
    try:
        out_dep, vulns = pypi.query(dep)
    except service.ServiceError as e:
        return {"outcome": "RAISES", "exc": type(e).__name__, "msg": str(e),
                "dep": None, "vulns": None, "json": None}
    except Exception as e:  # noqa: BLE001
        return {"outcome": "RAISES", "exc": type(e).__name__, "msg": str(e),
                "dep": None, "vulns": None, "json": None}
    rendered = JsonFormat(False, False)._format_dep(out_dep, vulns)
    return {"outcome": "RETURNED", "exc": "", "msg": classify(out_dep, vulns),
            "dep": out_dep, "vulns": vulns, "json": rendered}


def show(label, r):
    if r["outcome"] == "RAISES":
        print(f"{label}: RAISES {r['exc']}: {r['msg']}  -> no per-package JSON emitted")
    else:
        print(f"{label}: {r['msg']}  | json: {r['json']}")


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


def fresh_headers(clock, max_age):
    return {
        "Date": harness.http_date(clock),
        "Cache-Control": f"max-age={max_age}",
        "Content-Type": "application/json",
    }


def main(tmp: Path):
    clock = harness.FakeClock(start=1_000_000.0)
    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    url = pypi_url("foo", "1.0.0")
    empty_ok = (200, fresh_headers(clock, 100), harness.json_body({"vulnerabilities": []}))

    # ---- 1. Valid (fresh) cache -------------------------------------------
    banner("1. VALID (FRESH) CACHE: 200 once, then clock advances < max-age")
    d = tmp / "fresh"; d.mkdir()
    pypi, resp = make_pypi(d, clock, {url: [empty_ok]})
    r1 = run_query(pypi, dep)
    clock.advance(50)  # still within max-age=100
    r2 = run_query(pypi, dep)
    show("first ", r1)
    show("second", r2)
    print("network hits (expect 1):", resp.network_hits(url))

    # ---- 2. Stale (expired) cache -----------------------------------------
    banner("2. STALE (EXPIRED) CACHE + revalidation failure 503")
    clock2 = harness.FakeClock(start=2_000_000.0)
    d = tmp / "stale"; d.mkdir()
    first = (200, fresh_headers(clock2, 100), harness.json_body({"vulnerabilities": []}))
    stale_503 = (503, {"Date": harness.http_date(clock2)}, b"service unavailable")
    pypi, resp = make_pypi(d, clock2, {url: [first, stale_503]})
    run_query(pypi, dep)  # populate cache
    clock2.advance(500)   # now well past max-age=100
    out = run_query(pypi, dep)
    show("after expiry", out)
    print("network hits (expect 2):", resp.network_hits(url))

    # ---- 3. 404 -----------------------------------------------------------
    banner("3. HTTP 404 (package/version not on PyPI)")
    clock3 = harness.FakeClock(start=3_000_000.0)
    d = tmp / "n404"; d.mkdir()
    r404 = (404, {"Date": harness.http_date(clock3)}, b"nope")
    pypi, resp = make_pypi(d, clock3, {url: [r404]})
    out = run_query(pypi, dep)
    show("result", out)

    # ---- 4. 429 rate limit ------------------------------------------------
    banner("4. HTTP 429 (rate limited)")
    clock4 = harness.FakeClock(start=4_000_000.0)
    d = tmp / "n429"; d.mkdir()
    r429 = (429, {"Date": harness.http_date(clock4), "Retry-After": "60"}, b"slow down")
    pypi, resp = make_pypi(d, clock4, {url: [r429]})
    out = run_query(pypi, dep)
    show("result", out)

    # ---- 5. 5xx -----------------------------------------------------------
    banner("5. HTTP 500 (server error)")
    clock5 = harness.FakeClock(start=5_000_000.0)
    d = tmp / "n500"; d.mkdir()
    r500 = (500, {"Date": harness.http_date(clock5)}, b"boom")
    pypi, resp = make_pypi(d, clock5, {url: [r500]})
    out = run_query(pypi, dep)
    show("result", out)

    # ---- 6. Connection timeout (the reported "service timeout") -----------
    banner("6. CONNECT TIMEOUT (reported outage class)")
    import requests
    clock6 = harness.FakeClock(start=6_000_000.0)
    d = tmp / "timeout"; d.mkdir()
    def raise_timeout(request):
        raise requests.ConnectTimeout()
    pypi, resp = make_pypi(d, clock6, {url: [raise_timeout]})
    out = run_query(pypi, dep)
    show("result", out)


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        main(Path(td))
