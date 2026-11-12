"""
Deterministic, offline reproduction harness for pip-audit service behavior.

It wires the *real* pip-audit services (PyPI / OSV), the *real* CacheControl
middleware and pip-audit's *real* on-disk ``_SafeFileCache`` to a scripted HTTP
transport. No sockets are opened and no network is used.

Two things are faked:

* The clock: ``cachecontrol.controller.time.time`` is replaced by a value the
  test controls, so cache freshness/expiry can be exercised without sleeping.
* HTTP: a ``MockAdapter`` returns canned status codes, headers and bodies,
  while still routing storage/lookup through the genuine CacheController and
  the genuine FileCache used by pip-audit.
"""

from __future__ import annotations

import io
import json as _json
from dataclasses import dataclass, field
from email.utils import formatdate
from typing import Callable

import requests
from urllib3 import HTTPResponse

import cachecontrol.controller as cc_controller
from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.caches import FileCache

# ``pip_audit._cache._SafeFileCache`` only adds atomic-write safety on top of
# CacheControl's ``FileCache``; freshness/serialization behavior is identical, so
# the base class is sufficient and avoids an import-ordering cycle here.


class FakeClock:
    """A stand-in for ``time.time()`` whose value is set explicitly."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class RecordedRequest:
    method: str
    url: str
    at: float
    conditional: bool


@dataclass
class ScriptedResponder:
    """
    Returns canned responses keyed by URL.

    ``routes[url]`` is a list of ``(status, headers, body)`` turns. Each turn is
    consumed on a network (non-cached) request for that URL. When a route runs
    out of turns the last one is repeated. A turn may itself be a callable that
    takes the request and returns the tuple, useful for raising timeouts.
    """

    routes: dict[str, list]
    clock: FakeClock
    requests: list[RecordedRequest] = field(default_factory=list)

    def __call__(self, request) -> tuple[int, dict, bytes]:
        url = request.url
        turn_list = self.routes[url]
        prior_hits = len(self.requests_for(url))
        turn = turn_list[min(prior_hits, len(turn_list) - 1)]
        if isinstance(turn, Callable):
            turn = turn(request)
        status, headers, body = turn
        self.requests.append(
            RecordedRequest(
                method=request.method,
                url=url,
                at=self.clock(),
                conditional=bool(request.headers.get("If-None-Match") or
                                 request.headers.get("If-Modified-Since")),
            )
        )
        return status, headers, body

    def requests_for(self, url: str) -> list[RecordedRequest]:
        return [r for r in self.requests if r.url == url]

    def network_hits(self, url: str | None = None) -> int:
        if url is None:
            return len(self.requests)
        return len(self.requests_for(url))


class MockAdapter(CacheControlAdapter):
    """
    A CacheControlAdapter whose network layer is scripted.

    Cache lookup, conditional-header generation, serialization and the on-disk
    FileCache are all the genuine CacheControl implementations; only the actual
    HTTP exchange is replaced.
    """

    def __init__(self, responder: ScriptedResponder, cache, *a, **k) -> None:
        super().__init__(cache=cache, *a, **k)
        self.responder = responder

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

        status, headers, body = self.responder(request)

        def make_urllib3():
            return HTTPResponse(
                body=io.BytesIO(body),
                headers=dict(headers),
                status=status,
                preload_content=False,
                reason="Mock",
                request_url=request.url,
            )

        delivered = self.build_response(request, make_urllib3())
        if request.method in cacheable:
            # Hand a *fresh* response object to the serializer (it reads/resets
            # the fp itself) so the delivered body is left intact.
            self.controller.cache_response(request, make_urllib3())
        return delivered


def http_date(clock: FakeClock) -> str:
    return formatdate(clock(), usegmt=True)


def make_session(cache_dir, clock: FakeClock, routes: dict[str, list]):
    """Build a requests session with the mock transport and real file cache."""
    # CacheControl reads "now" through module-level ``time.time``; redirect that
    # single reference to our controllable clock so freshness follows it exactly.
    cc_controller.time.time = clock
    responder = ScriptedResponder(routes=routes, clock=clock)
    session = requests.Session()
    adapter = MockAdapter(responder, cache=FileCache(str(cache_dir)))
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session, responder


def patch_clock(clock: FakeClock) -> None:
    cc_controller.time.time = clock


def json_body(payload: dict | list) -> bytes:
    return _json.dumps(payload).encode()
