"""Explicit, bounded Langfuse v2 readback; no exporter, polling job or raw output."""
from __future__ import annotations

import base64
import json
import math
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .delivery_receipts import MAX_OBSERVATIONS

_TRACE = re.compile(r"[0-9a-f]{32}")
_SPAN = re.compile(r"[0-9a-f]{16}")
_PAGE_BYTES = 1024 * 1024
_CURSOR_BYTES = 2048


class ReadbackError(RuntimeError):
    """Fixed diagnostic code only: never include URLs, response bodies or keys."""


class ReadWindowError(ValueError):
    """The requested query identity/window cannot be covered by this reader."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise ReadbackError("redirect_refused")


@dataclass(frozen=True)
class _Observation:
    id: str
    trace_id: str
    parent_id: str | None
    ended: bool


@dataclass(frozen=True)
class Readback:
    """A complete bounded query, not proof of delivery or of all agent work."""

    trace_id: str
    pages: int
    _observations: tuple[_Observation, ...]

    @property
    def complete(self):
        return True  # instances are returned only after exhausting every cursor

    @property
    def observations(self):
        # Returned envelopes must not mutate the retained normalized readback.
        return tuple({"id": row.id, "trace_id": row.trace_id,
                      "parent_id": row.parent_id, "ended": row.ended}
                     for row in self._observations)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("non-finite JSON number")


def _epoch(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must have a timezone")
    return parsed.timestamp()


def _stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _window(trace_id, start_time, end_time):
    if not isinstance(trace_id, str) or not _TRACE.fullmatch(trace_id):
        raise ReadWindowError("invalid trace identity")
    if any(type(t) not in (int, float) or not math.isfinite(t)
           for t in (start_time, end_time)):
        raise ReadWindowError("invalid time window")
    if not 0 <= start_time < end_time or end_time - start_time > 86400:
        raise ReadWindowError("time window must be positive and at most 24 hours")


def _response_length(response):
    """Require an entire successful HTTP message, not a parseable body prefix."""
    headers = response.headers
    if response.status != 200 or headers.get("Content-Range") is not None:
        raise ReadbackError("incomplete_response")
    lengths = headers.get_all("Content-Length", [])
    transfers = headers.get_all("Transfer-Encoding", [])
    if (len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers)
            or (transfers and transfers[0].strip().lower() != "chunked")):
        raise ReadbackError("invalid_http_framing")
    if not lengths:
        return None  # chunk decoder or a clean connection EOF frames this message
    length = lengths[0].strip()
    if not re.fullmatch(r"[0-9]{1,10}", length):
        raise ReadbackError("invalid_http_framing")
    if int(length) > _PAGE_BYTES:
        raise ReadbackError("response_too_large")
    return int(length)


class ObservationReader:
    """Read one explicit trace/project/window. Construction performs no requests.

    Only the v2 API is supported; an unavailable API is unverified, never an
    automatic downgrade. Keys remain in memory. No raw response is retained.
    Socket operations have a finite timeout; the query's elapsed deadline is
    checked between open/read/page operations (not a hard process watchdog).
    """

    def __init__(self, base_url: str, public_key: str, secret_key: str, *,
                 project_id: str, timeout_seconds: float = 5.0, max_pages: int = 8):
        parsed = urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or any(c.isspace() or ord(c) < 32 for c in base_url)):
            raise ValueError("an explicit HTTPS endpoint is required")
        if (not isinstance(project_id, str) or not 1 <= len(project_id) <= 128
                or any(ord(c) < 32 for c in project_id)):
            raise ValueError("invalid project identity")
        for key in (public_key, secret_key):
            if not isinstance(key, str) or not key or len(key) > 512 or any(c.isspace() for c in key):
                raise ValueError("invalid read credential")
        if ":" in public_key:
            raise ValueError("invalid read credential")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 10 or type(max_pages) is not int
                or not 1 <= max_pages <= 16):
            raise ValueError("invalid read limits")
        self._url = base_url.rstrip("/") + "/api/public/v2/observations"
        self._authorization = "Basic " + base64.b64encode(
            f"{public_key}:{secret_key}".encode()).decode("ascii")
        self._project = project_id
        self._timeout = timeout_seconds
        self._max_pages = max_pages
        self._clock = time.monotonic
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def _remaining(self, deadline):
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise ReadbackError("deadline_exceeded")
        return remaining

    def _page(self, query, deadline):
        request = Request(self._url + "?" + urlencode(query),
                          headers={"Authorization": self._authorization, "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self._remaining(deadline)) as response:
                expected_length = _response_length(response)
                chunks, count = [], 0
                while True:
                    self._remaining(deadline)
                    chunk = response.read1(min(65536, _PAGE_BYTES + 1 - count))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    count += len(chunk)
                    if count > _PAGE_BYTES:
                        raise ReadbackError("response_too_large")
                self._remaining(deadline)
                if expected_length is not None and count != expected_length:
                    raise ReadbackError("incomplete_response")
                return json.loads(b"".join(chunks), object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
        except HTTPError as error:
            error.close()
            raise ReadbackError("transport_failed") from None
        except OSError:
            raise ReadbackError("transport_failed") from None
        except HTTPException:
            raise ReadbackError("incomplete_response") from None
        except (ValueError, RecursionError):
            raise ReadbackError("invalid_response") from None

    def _observation(self, row, trace_id, start_time, end_time):
        try:
            if not isinstance(row, dict):
                raise ValueError
            oid, parent = row["id"], row["parentObservationId"]
            if (not isinstance(oid, str) or not _SPAN.fullmatch(oid)
                    or (parent is not None and (not isinstance(parent, str) or not _SPAN.fullmatch(parent)))
                    or row["traceId"] != trace_id or row["projectId"] != self._project):
                raise ValueError
            started = _epoch(row["startTime"])
            if not start_time <= started < end_time:
                raise ValueError
            ended = row["endTime"]
            if ended is not None and not started <= _epoch(ended) <= end_time:
                raise ValueError
            return _Observation(oid, trace_id, parent, ended is not None)
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ReadbackError("invalid_observation") from None

    def read(self, trace_id: str, *, start_time: float, end_time: float) -> Readback:
        _window(trace_id, start_time, end_time)
        deadline = self._clock() + self._timeout
        query = {"fields": "core", "traceId": trace_id, "limit": 100,
                 "fromStartTime": _stamp(start_time), "toStartTime": _stamp(end_time)}
        observations, seen, cursors = [], set(), set()
        for page_number in range(1, self._max_pages + 1):
            page = self._page(query, deadline)
            if (not isinstance(page, dict) or not isinstance(page.get("data"), list)
                    or not isinstance(page.get("meta"), dict)):
                raise ReadbackError("invalid_response")
            if len(observations) + len(page["data"]) > MAX_OBSERVATIONS:
                raise ReadbackError("observation_limit")
            for row in page["data"]:
                item = self._observation(row, trace_id, start_time, end_time)
                if item.id in seen:
                    raise ReadbackError("duplicate_observation")
                seen.add(item.id)
                observations.append(item)
            cursor = page["meta"].get("cursor")
            if cursor is None:
                return Readback(trace_id, page_number, tuple(observations))
            if (not isinstance(cursor, str) or not 0 < len(cursor) <= _CURSOR_BYTES
                    or cursor in cursors):
                raise ReadbackError("invalid_cursor")
            cursors.add(cursor)
            query["cursor"] = cursor
        raise ReadbackError("page_limit")
