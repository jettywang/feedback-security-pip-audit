"""
End-to-end behavior of query-status reporting under a controllable clock and
scripted HTTP responses, exercising the *real* CacheControl machinery.

These tests run fully offline: the network adapter is replaced while cache
lookup, serialization, freshness and the on-disk file cache stay genuine.
They pin down the distinction between "queried and clean" and "never got a
result" for every service response class.
"""

from __future__ import annotations

import io
from email.utils import formatdate

import pytest
from packaging.version import Version
from urllib3 import HTTPResponse

import cachecontrol.controller as cc_controller
from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.caches import FileCache

import pip_audit._service as service


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ScriptedAdapter(CacheControlAdapter):
    """CacheControlAdapter with a scripted, in-memory network layer."""

    def __init__(self, turns, _clock, cache, **kwargs):
        super().__init__(cache=cache, **kwargs)
        self._turns = turns
        self.network_hits = 0

    def send(
        self,
        request,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
        cacheable_methods=None,
    ):
        cacheable = cacheable_methods or self.cacheable_methods
        if request.method in cacheable:
            cached = self.controller.cached_request(request)
            if cached:
                return self.build_response(request, cached, from_cache=True)
            request.headers.update(self.controller.conditional_headers(request))

        status, headers, body = self._turns[min(self.network_hits, len(self._turns) - 1)]
        self.network_hits += 1

        def make():
            return HTTPResponse(
                body=io.BytesIO(body),
                headers=dict(headers),
                status=status,
                preload_content=False,
                reason="Mock",
                request_url=request.url,
            )

        delivered = self.build_response(request, make())
        if request.method in cacheable:
            self.controller.cache_response(request, make())
        return delivered


def _service(tmp_path, monkeypatch, clock, turns):
    monkeypatch.setattr(cc_controller.time, "time", clock)
    import requests

    session = requests.Session()
    adapter = ScriptedAdapter(turns, clock, FileCache(str(tmp_path)))
    session.mount("https://", adapter)
    pypi = service.PyPIService(tmp_path)
    pypi.session = session
    return pypi, adapter


def _headers(clock, **extra):
    return {
        "Date": formatdate(clock(), usegmt=True),
        "Content-Type": "application/json",
        **extra,
    }


def _json(payload):
    import json

    return json.dumps(payload).encode()


def _dep():
    return service.ResolvedDependency("foo", Version("1.0.0"))


def test_fresh_cache_serves_without_network_and_is_success(tmp_path, monkeypatch):
    clock = FakeClock()
    turns = [(200, _headers(clock, **{"Cache-Control": "max-age=100"}), _json({"vulnerabilities": []}))]
    pypi, adapter = _service(tmp_path, monkeypatch, clock, turns)

    dep, vulns = pypi.query(_dep())
    assert not dep.is_skipped()
    assert dep.audit_status is service.AuditStatus.Success
    assert vulns == []

    clock.advance(50)  # still inside max-age
    dep2, vulns2 = pypi.query(_dep())
    assert dep2.audit_status is service.AuditStatus.Success
    assert vulns2 == []
    assert adapter.network_hits == 1  # second query served from cache


def test_expired_cache_revalidates_and_surfaces_error(tmp_path, monkeypatch):
    clock = FakeClock()
    turns = [
        (200, _headers(clock, **{"Cache-Control": "max-age=100"}), _json({"vulnerabilities": []})),
        (503, _headers(clock), b"unavailable"),
    ]
    pypi, adapter = _service(tmp_path, monkeypatch, clock, turns)

    pypi.query(_dep())  # populate cache
    clock.advance(500)  # force revalidation; the stale entry must not be trusted

    with pytest.raises(service.ServiceError):
        pypi.query(_dep())
    assert adapter.network_hits == 2

    # Contained at the batch boundary: the package is marked as an error skip.
    results = dict(pypi.query_all(iter([_dep()])))
    (skipped, vulns) = next(iter(results.items()))
    assert skipped.audit_status is service.AuditStatus.Error
    assert skipped.audit_status.has_valid_result is False
    assert vulns == []


def test_404_is_not_known_skip(tmp_path, monkeypatch):
    clock = FakeClock()
    turns = [(404, _headers(clock), b"missing")]
    pypi, _ = _service(tmp_path, monkeypatch, clock, turns)

    dep, vulns = pypi.query(_dep())
    assert dep.is_skipped()
    assert dep.audit_status is service.AuditStatus.NotKnown
    assert dep.audit_status.has_valid_result is False
    assert vulns == []


@pytest.mark.parametrize("status", [429, 500, 503])
def test_rate_limit_and_5xx_become_error_skips_in_query_all(tmp_path, monkeypatch, status):
    clock = FakeClock()
    turns = [(status, _headers(clock, **{"Retry-After": "60"}), b"problem")]
    pypi, _ = _service(tmp_path, monkeypatch, clock, turns)

    with pytest.raises(service.ServiceError):
        pypi.query(_dep())

    results = dict(pypi.query_all(iter([_dep()])))
    (skipped, vulns) = next(iter(results.items()))
    assert skipped.is_skipped()
    assert skipped.audit_status is service.AuditStatus.Error
    assert vulns == []


def test_query_all_continues_after_a_failure(tmp_path, monkeypatch):
    """One failing package must not prevent later packages from being audited."""
    clock = FakeClock()

    class RoutingAdapter(ScriptedAdapter):
        def __init__(self, by_url, clock, cache):
            super().__init__([], clock, cache)
            self._by_url = by_url
            self._hits_by_url: dict[str, int] = {}

        def send(self, request, *args, **kwargs):
            cacheable = kwargs.get("cacheable_methods") or self.cacheable_methods
            if request.method in cacheable:
                cached = self.controller.cached_request(request)
                if cached:
                    return self.build_response(request, cached, from_cache=True)
                request.headers.update(self.controller.conditional_headers(request))
            idx = self._hits_by_url.get(request.url, 0)
            status, headers, body = self._by_url[request.url][idx]
            self._hits_by_url[request.url] = idx + 1
            self.network_hits += 1

            def make():
                return HTTPResponse(
                    body=io.BytesIO(body),
                    headers=dict(headers),
                    status=status,
                    preload_content=False,
                    reason="Mock",
                    request_url=request.url,
                )

            delivered = self.build_response(request, make())
            self.controller.cache_response(request, make())
            return delivered

    import requests

    monkeypatch.setattr(cc_controller.time, "time", clock)
    deps = [
        service.ResolvedDependency("alpha", Version("1.0.0")),
        service.ResolvedDependency("beta", Version("2.0.0")),
        service.ResolvedDependency("gamma", Version("3.0.0")),
    ]
    by_url = {
        "https://pypi.org/pypi/alpha/1.0.0/json": [
            (200, _headers(clock), _json({"vulnerabilities": []}))
        ],
        "https://pypi.org/pypi/beta/2.0.0/json": [(500, _headers(clock), b"boom")],
        "https://pypi.org/pypi/gamma/3.0.0/json": [
            (200, _headers(clock), _json({"vulnerabilities": []}))
        ],
    }
    session = requests.Session()
    adapter = RoutingAdapter(by_url, clock, FileCache(str(tmp_path)))
    session.mount("https://", adapter)
    pypi = service.PyPIService(tmp_path)
    pypi.session = session

    results = list(pypi.query_all(iter(deps)))
    statuses = {dep.canonical_name: dep.audit_status for dep, _ in results}
    assert statuses == {
        "alpha": service.AuditStatus.Success,
        "beta": service.AuditStatus.Error,
        "gamma": service.AuditStatus.Success,
    }
    # All three packages are represented even though the middle one failed.
    assert len(results) == 3
