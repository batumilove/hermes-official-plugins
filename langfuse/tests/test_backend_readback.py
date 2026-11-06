"""Backend evidence contracts, using synthetic HTTP responses and no credentials."""
import base64
import io
import json
from datetime import datetime, timezone
from email.message import Message
from urllib.parse import parse_qs, urlsplit

import pytest

from langfuse_plugin.backend_readback import ObservationReader, ReadbackError


TRACE = "a" * 32
ROOT = "b" * 16
CHILD = "c" * 16
START = 1793977000.0


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def observation(oid=ROOT, parent=None, **changes):
    row = {"id": oid, "traceId": TRACE, "projectId": "synthetic-project",
           "parentObservationId": parent, "startTime": stamp(START + 1),
           "endTime": stamp(START + 2)}
    return dict(row, **changes)


class Transport:
    def __init__(self, *pages):
        self.pages = list(pages)
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        page = self.pages.pop(0)
        if isinstance(page, BaseException):
            raise page
        data = page if isinstance(page, bytes) else json.dumps(page).encode()
        response = io.BytesIO(data)
        response.headers = Message()
        response.headers["Content-Length"] = str(len(data))
        response.status = 200
        return response


def reader(*pages, **kwargs):
    transport = Transport(*pages)
    result = ObservationReader("https://synthetic.invalid", "pk-synthetic",
                               "sk-synthetic", project_id="synthetic-project", **kwargs)
    result._opener = transport
    return result, transport


def test_cursor_exhaustion_including_empty_page_is_required():
    r, transport = reader({"data": [observation()], "meta": {"cursor": "next"}},
                          {"data": [], "meta": {"cursor": "last"}},
                          {"data": [observation(CHILD, ROOT)], "meta": {"cursor": None}})
    result = r.read(TRACE, start_time=START, end_time=START + 10)
    assert result.complete and result.pages == 3
    assert result.observations == (
        {"id": ROOT, "trace_id": TRACE, "parent_id": None, "ended": True},
        {"id": CHILD, "trace_id": TRACE, "parent_id": ROOT, "ended": True})
    for index, (request, timeout) in enumerate(transport.requests):
        query = parse_qs(urlsplit(request.full_url).query)
        assert query["traceId"] == [TRACE] and query["fields"] == ["core"]
        assert query["fromStartTime"] == [stamp(START)]
        assert query["toStartTime"] == [stamp(START + 10)]
        assert query.get("cursor") == (["next"] if index == 1 else ["last"] if index == 2 else None)
        auth = base64.b64encode(b"pk-synthetic:sk-synthetic").decode()
        assert request.get_header("Authorization") == "Basic " + auth
        assert 0 < timeout <= 5


@pytest.mark.parametrize("changes", [
    {"traceId": "d" * 32}, {"projectId": "other"}, {"id": "invalid"},
    {"parentObservationId": "invalid"}, {"startTime": "2026-11-06"},
    {"startTime": stamp(START - 1)}, {"startTime": stamp(START + 10)},
    {"endTime": stamp(START)}, {"endTime": "bad"}])
def test_wrong_identity_or_invalid_timestamps_never_become_evidence(changes):
    r, _ = reader({"data": [observation(**changes)], "meta": {}})
    with pytest.raises(ReadbackError, match="invalid_observation"):
        r.read(TRACE, start_time=START, end_time=START + 10)


def test_open_observation_is_preserved_as_open_not_delivered():
    r, _ = reader({"data": [observation(endTime=None)], "meta": {}})
    result = r.read(TRACE, start_time=START, end_time=START + 10)
    assert result.complete and result.observations[0]["ended"] is False


@pytest.mark.parametrize("pages", [
    ({"data": [observation(), observation()], "meta": {}},),
    ({"data": [observation()], "meta": {"cursor": "x"}},
     {"data": [observation()], "meta": {}}),
    ({"data": [], "meta": {"cursor": "x"}},
     {"data": [], "meta": {"cursor": "x"}}),
    ({"data": [], "meta": {"cursor": "x"}},)])
def test_duplicate_rows_and_unfinished_pagination_fail_closed(pages):
    r, _ = reader(*pages, max_pages=len(pages))
    with pytest.raises(ReadbackError):
        r.read(TRACE, start_time=START, end_time=START + 10)


@pytest.mark.parametrize("page", [b"not json", b"[]", b'{"data":[],"data":[],"meta":{}}',
                                  {"data": [], "meta": {"cursor": 1}}, {"data": []},
                                  {"data": [], "meta": None}, b" " * (1048576 + 1)])
def test_malformed_or_oversized_response_has_no_positive_prefix(page):
    r, _ = reader(page)
    with pytest.raises(ReadbackError):
        r.read(TRACE, start_time=START, end_time=START + 10)


def test_backend_errors_are_content_free():
    r, _ = reader(OSError("SENSITIVE_SENTINEL"))
    with pytest.raises(ReadbackError) as caught:
        r.read(TRACE, start_time=START, end_time=START + 10)
    assert str(caught.value) == "transport_failed"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("url", ["http://synthetic.invalid", "https://u:p@synthetic.invalid",
                                "https://synthetic.invalid?key=secret", "https://synthetic.invalid/#x"])
def test_only_explicit_https_endpoint_without_embedded_credentials(url):
    with pytest.raises(ValueError):
        ObservationReader(url, "pk-synthetic", "sk-synthetic", project_id="synthetic-project")


def test_unknown_response_fields_never_reach_retained_evidence():
    r, _ = reader({"data": [observation(input="SENSITIVE_SENTINEL", output="SENSITIVE_SENTINEL")],
                   "meta": {}, "debug": "SENSITIVE_SENTINEL"})
    result = r.read(TRACE, start_time=START, end_time=START + 10)
    assert "SENSITIVE_SENTINEL" not in repr(result)


def test_observation_cap_is_global_across_pages():
    pages = [{"data": [observation(f"{i:016x}") for i in range(start, start + 100)],
              "meta": {"cursor": str(start)}} for start in (0, 100, 200)]
    r, transport = reader(*pages)
    with pytest.raises(ReadbackError, match="observation_limit"):
        r.read(TRACE, start_time=START, end_time=START + 10)
    assert len(transport.requests) == 3


def test_elapsed_budget_is_shared_by_pages():
    r, transport = reader({"data": [], "meta": {"cursor": "x"}})
    ticks = iter([0.0, 1.0, 2.0, 3.0, 6.0])
    r._clock = lambda: next(ticks)
    with pytest.raises(ReadbackError, match="deadline_exceeded"):
        r.read(TRACE, start_time=START, end_time=START + 10)
    assert len(transport.requests) == 1


@pytest.mark.parametrize("start, end", [(True, START + 10), (START, float("nan")),
                                       (START, START), (START, START + 86401)])
def test_invalid_window_is_rejected_before_network(start, end):
    r, transport = reader()
    with pytest.raises(ValueError):
        r.read(TRACE, start_time=start, end_time=end)
    assert not transport.requests


def test_snapshot_is_not_mutable_through_returned_rows():
    r, _ = reader({"data": [observation()], "meta": {}})
    result = r.read(TRACE, start_time=START, end_time=START + 10)
    result.observations[0]["ended"] = False
    assert result.observations[0]["ended"] is True


@pytest.mark.parametrize("headers", [
    [("Content-Length", "-1")], [("Content-Length", "12,12")],
    [("Content-Length", "22"), ("Content-Length", "22")],
    [("Content-Length", "22"), ("Transfer-Encoding", "chunked")],
    [("Transfer-Encoding", "gzip")]])
def test_ambiguous_http_framing_is_refused(headers):
    from types import SimpleNamespace
    r, transport = reader({"data": [], "meta": {}})
    response = transport.open(None, timeout=1)
    response.headers = Message()
    for name, value in headers:
        response.headers[name] = value
    r._opener = SimpleNamespace(open=lambda *args, **kwargs: response)
    with pytest.raises(ReadbackError, match="invalid_http_framing"):
        r.read(TRACE, start_time=START, end_time=START + 10)
