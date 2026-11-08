"""Explicit single-canary retirement; importing this module never deletes data.

The separately approved controller supplies its random task nonce and independently
verified trace/root pins. This is not a project retention policy or a general purge.
Successful retirement is sampled API absence, not proof of forensic/backup erasure.
"""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

from .backend_readback import (
    ObservationReader, ReadbackError, _response_length, _unique_object,
    _invalid_constant, _stamp, _window,
)


class CleanupRefused(RuntimeError):
    """Fixed categories only; never include backend bodies or credentials."""


def _require_producer_gone(pid):
    # Refuse PID reuse as well: it is safer to require recovery than to infer
    # termination from a new process with the old numeric identity.
    if not Path('/proc/self/stat').is_file() or Path('/proc', str(pid)).exists():
        raise CleanupRefused('producer_not_proven_gone')


class _CanaryRequests:
    def __init__(self, reader: ObservationReader, *, task_id: str,
                 producer_pid: int, start_time: float, end_time: float):
        if (type(reader) is not ObservationReader or reader._api_version != 'v1'
                or not isinstance(task_id, str)
                or re.fullmatch(r'telemetry-canary-[0-9a-f]{32}', task_id) is None
                or type(producer_pid) is not int or producer_pid <= 1 or producer_pid == os.getpid()):
            raise CleanupRefused('invalid_canary_scope')
        if (any(type(t) not in (int, float) or not math.isfinite(t) for t in (start_time, end_time))
                or not 0 <= start_time < end_time or end_time - start_time > 86400):
            raise CleanupRefused('invalid_canary_window')
        self._reader = reader
        self._task = task_id
        self._producer, self._creator = producer_pid, os.getpid()
        self._start, self._end = start_time, end_time
        self._expires = reader._clock() + 60
        self._requests = 0
        self._delete_attempts = 0

    def _guard(self):
        if os.getpid() != self._creator or self._reader._clock() >= self._expires:
            raise CleanupRefused('cleanup_owner_or_deadline_changed')
        _require_producer_gone(self._producer)

    def _request(self, method, url, *, allow_missing=False):
        self._guard()
        if self._requests >= 10:
            raise CleanupRefused('cleanup_request_limit')
        self._requests += 1
        request = Request(url, headers={'Authorization': self._reader._authorization,
                                        'Accept': 'application/json'}, method=method)
        deadline = min(self._expires, self._reader._clock() + self._reader._timeout)
        try:
            if method == 'DELETE':
                self._delete_attempts += 1
            with self._reader._opener.open(request, timeout=self._reader._remaining(deadline)) as response:
                expected = _response_length(response)
                chunks, size = [], 0
                while True:
                    self._reader._remaining(deadline)
                    chunk = response.read1(min(65536, 262145 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 262144:
                        raise CleanupRefused('cleanup_response_limit')
                self._reader._remaining(deadline)
                if expected is not None and expected != size:
                    raise CleanupRefused('cleanup_response_incomplete')
                value = json.loads(b''.join(chunks), object_pairs_hook=_unique_object,
                                   parse_constant=_invalid_constant)
        except HTTPError as error:
            status = error.code
            error.close()
            if allow_missing and method == 'GET' and status == 404:
                self._guard()
                return None
            raise CleanupRefused('cleanup_transport_failed') from None
        except CleanupRefused:
            raise
        except Exception:
            raise CleanupRefused('cleanup_transport_or_schema_failed') from None
        self._guard()
        if not isinstance(value, dict):
            raise CleanupRefused('cleanup_schema_invalid')
        return value


@contextmanager
def _journal_folder(path):
    """Walk from / with directory descriptors; never follow ancestor symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.name:
        raise CleanupRefused('private_delete_journal_required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:-1]:
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700 or st.st_nlink == 0:
            raise CleanupRefused('private_delete_journal_required')
        yield fd, path.name
    finally:
        os.close(fd)


class CanaryTraceRetirement(_CanaryRequests):
    """One exact canary after producer exit; a durable journal fences DELETE.

    Construction is inert. The separately approved parent owns the generation's
    random task nonce, time window, project and journal directory. No constructor
    argument, key or saved file is interpreted as activation approval.
    """

    def __init__(self, reader, *, task_id, trace_id, root_id, producer_pid,
                 start_time, end_time, delete_journal):
        super().__init__(reader, task_id=task_id, producer_pid=producer_pid,
                         start_time=start_time, end_time=end_time)
        try:
            _window(trace_id, start_time, end_time)
        except ValueError:
            raise CleanupRefused('invalid_canary_scope') from None
        if not isinstance(root_id, str) or re.fullmatch(r'[0-9a-f]{16}', root_id) is None:
            raise CleanupRefused('invalid_canary_scope')
        self._trace, self._root = trace_id, root_id
        self._journal = Path(delete_journal)
        self._used = False

    def _journal_bytes(self):
        return json.dumps({'schema': 1, 'task_id': self._task, 'trace_id': self._trace,
            'root_id': self._root, 'project_sha256': hashlib.sha256(self._reader._project.encode()).hexdigest(),
            'endpoint_sha256': hashlib.sha256(self._reader._url.encode()).hexdigest(),
            'start_time': self._start, 'end_time': self._end},
            sort_keys=True, separators=(',', ':')).encode()

    def _claim_delete(self):
        self._guard()
        with _journal_folder(self._journal) as (folder, name):
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=folder)
            except FileExistsError:
                raise CleanupRefused('delete_already_claimed') from None
            # A failed/partial write intentionally leaves the claim in place.
            # Another process must not retry a possibly executed DELETE.
            with os.fdopen(fd, 'wb') as stream:
                stream.write(self._journal_bytes()); stream.flush()
                os.fchmod(stream.fileno(),0o400); os.fsync(stream.fileno())
            os.fsync(folder)
        self._guard()

    def _require_delete_claim(self):
        with _journal_folder(self._journal) as (folder, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
            with os.fdopen(fd, 'rb') as stream:
                st = os.fstat(stream.fileno())
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1
                        or stat.S_IMODE(st.st_mode) not in (0o400, 0o600) or st.st_size > 4096
                        or stream.read(4097) != self._journal_bytes()):
                    raise CleanupRefused('delete_journal_changed')

    @classmethod
    def from_journal(cls, reader, *, task_id, producer_pid, start_time, end_time, delete_journal):
        """Reconstruct read-only confirmation scope, never a new deletion claim."""
        with _journal_folder(delete_journal) as (folder, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
            with os.fdopen(fd, 'rb') as stream:
                st = os.fstat(stream.fileno())
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1
                        or stat.S_IMODE(st.st_mode) not in (0o400,0o600) or st.st_size > 4096):
                    raise CleanupRefused('delete_journal_changed')
                try:
                    record = json.loads(stream.read(4097), object_pairs_hook=_unique_object,
                                        parse_constant=_invalid_constant)
                except Exception:
                    raise CleanupRefused('delete_journal_changed') from None
        if not isinstance(record, dict):
            raise CleanupRefused('delete_journal_changed')
        scope = cls(reader, task_id=task_id, trace_id=record.get('trace_id'), root_id=record.get('root_id'),
            producer_pid=producer_pid, start_time=start_time, end_time=end_time, delete_journal=delete_journal)
        scope._guard()
        scope._require_delete_claim()  # includes exact task/project/endpoint and schema
        return scope

    @classmethod
    def discover(cls, reader, *, task_id, producer_pid, start_time, end_time, delete_journal):
        """Read-only discovery by the pre-export nonce, not a cached Receipt proof.

        An absent result means unobserved/pending, never verified retirement.
        This also identifies a partial root when normal receipt sealing failed.
        """
        probe = _CanaryRequests(reader, task_id=task_id,
            producer_pid=producer_pid, start_time=start_time, end_time=end_time)
        probe._guard()
        from urllib.parse import urlencode
        query = {'limit': 2, 'page': 1, 'fromStartTime': _stamp(start_time),
                 'toStartTime': _stamp(end_time), 'filter': json.dumps([
                     {'type': 'stringObject', 'column': 'metadata', 'key': 'task_id',
                      'operator': '=', 'value': task_id}])}
        page = probe._request('GET', reader._url + '?' + urlencode(query))
        meta, rows = page.get('meta'), page.get('data')
        if (not isinstance(meta, dict) or not isinstance(rows, list)
                or any(type(meta.get(k)) is not int for k in ('page','limit','totalItems','totalPages'))
                or meta['page'] != 1 or meta['limit'] != 2 or meta['totalItems'] not in (0,1,2)
                or meta['totalPages'] != (1 if meta['totalItems'] else 0) or len(rows) != meta['totalItems']):
            raise CleanupRefused('canary_discovery_ambiguous')
        if not rows:
            return None
        raw = rows[0]
        if not isinstance(raw, dict):
            raise CleanupRefused('canary_discovery_invalid')
        trace_id, root_id = raw.get('traceId'), raw.get('id')
        scope = cls(reader, task_id=task_id, trace_id=trace_id, root_id=root_id,
            producer_pid=producer_pid, start_time=start_time, end_time=end_time,
            delete_journal=delete_journal)
        scope._validate_root(raw)
        seen={scope._root}
        for other in rows[1:]:
            if not isinstance(other,dict) or other.get('traceId') != scope._trace:
                raise CleanupRefused('canary_discovery_ambiguous')
            item=cls(reader,task_id=task_id,trace_id=scope._trace,root_id=other.get('id'),
                producer_pid=producer_pid,start_time=start_time,end_time=end_time,delete_journal=delete_journal)
            item._validate_root(other)
            if item._root in seen:
                raise CleanupRefused('canary_discovery_ambiguous')
            seen.add(item._root)
        return scope

    def _validate_root(self, raw):
        try:
            row = self._reader._observation(raw, self._trace, self._start, self._end)
        except ReadbackError:
            raise CleanupRefused('canary_root_invalid') from None
        metadata = raw.get('metadata')
        # Open roots can belong to interrupted canaries. They are cleanup
        # candidates, never successful delivery evidence.
        if (row.id != self._root or row.is_root is not True
                or metadata.get('task_id') != self._task or metadata.get('source') != 'hermes'
                or metadata.get('platform') != 'telemetry-canary'
                or metadata.get('capture_mode') != 'metadata'):
            raise CleanupRefused('canary_ownership_mismatch')

    def retire(self):
        """Submit at most one DELETE; never retry an ambiguous write."""
        if self._used:
            raise CleanupRefused('cleanup_already_used')
        self._used = True
        self._guard()
        reader = self._reader
        base = reader._url.removesuffix('/api/public/observations')
        from urllib.parse import urlencode
        query = {'traceId': self._trace, 'limit': 1, 'page': 1,
                 'fromStartTime': _stamp(self._start), 'toStartTime': _stamp(self._end),
                 'filter': json.dumps([{'type': 'string', 'column': 'id',
                                       'operator': '=', 'value': self._root}])}
        page = self._request('GET', reader._url + '?' + urlencode(query))
        expected_meta = {'page': 1, 'limit': 1, 'totalItems': 1, 'totalPages': 1}
        if (not isinstance(page.get('meta'), dict)
                or any(type(page['meta'].get(k)) is not int or page['meta'][k] != v
                       for k, v in expected_meta.items())
                or not isinstance(page.get('data'), list) or len(page['data']) != 1):
            raise CleanupRefused('canary_root_not_unique')
        self._validate_root(page['data'][0])
        trace_url = base + '/api/public/traces/' + self._trace
        trace = self._request('GET', trace_url)
        if trace.get('id') != self._trace or trace.get('projectId') != reader._project:
            raise CleanupRefused('canary_trace_identity_mismatch')
        self._claim_delete()
        deleted = self._request('DELETE', trace_url)
        if deleted.get('message') != 'Trace deleted successfully':
            raise CleanupRefused('cleanup_write_unverified')
        return self.confirm()

    def confirm(self):
        """Read-only recovery after a matching durable DELETE claim; never writes."""
        self._guard()
        self._require_delete_claim()
        reader = self._reader
        base=reader._url.removesuffix('/api/public/observations')
        project=self._request('GET',base+'/api/public/projects')
        projects=project.get('data')
        if (not isinstance(projects,list) or len(projects)!=1 or not isinstance(projects[0],dict)
                or projects[0].get('id') != reader._project):
            raise CleanupRefused('cleanup_project_binding_changed')
        trace_url = base + '/api/public/traces/' + self._trace
        # Deletion is asynchronous. An acknowledgement alone is never retirement.
        # This bounded pass may return pending; later recovery requires a new,
        # separately owned readback, never another automatic DELETE or export.
        for attempt in range(4):
            if attempt:
                time.sleep(1)
            if self._request('GET', trace_url, allow_missing=True) is None:
                self._guard()
                remaining = reader.read(self._trace, start_time=self._start, end_time=self._end)
                self._guard()
                if remaining.complete and not remaining.observations:
                    return {'status': 'canary_api_retirement_verified', 'delete_claims': 1,
                            'delete_attempts_current_process': self._delete_attempts,
                            'trace_absent': True, 'observations_absent': True,
                            'backup_or_forensic_erasure': False}
                raise CleanupRefused('cleanup_observations_remain')
        return {'status': 'canary_deletion_pending', 'delete_claims': 1,
                'delete_attempts_current_process': self._delete_attempts,
                'trace_absent': False, 'observations_absent': False,
                'backup_or_forensic_erasure': False}
