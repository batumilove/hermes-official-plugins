"""Offline single-canary deletion boundaries; no keys, backend or /proc authority."""
import io
import json
import os
from email.message import Message
from urllib.error import HTTPError

import pytest

from langfuse_plugin import canary_cleanup as module
from langfuse_plugin.backend_readback import ObservationReader


TRACE, ROOT, TASK = 'a' * 32, 'b' * 16, 'telemetry-canary-' + 'c' * 32
native_journal = pytest.mark.skipif(
    not (all(hasattr(os, name) for name in ('getuid', 'O_NOFOLLOW', 'O_DIRECTORY'))
         and os.open in os.supports_dir_fd),
    reason='native POSIX directory-descriptor journal custody required')


def root_page(**metadata):
    return {'data': [{'id': ROOT, 'traceId': TRACE, 'projectId': 'synthetic-project',
             'parentObservationId': None, 'startTime': '1970-01-01T00:16:41+00:00',
             'endTime': '1970-01-01T00:16:42+00:00',
             'metadata': dict(hermes_receipt_root=True, task_id=TASK, source='hermes',
                              platform='telemetry-canary', capture_mode='metadata', **metadata)}],
            'meta': {'page': 1, 'limit': 1, 'totalItems': 1, 'totalPages': 1}}


class Transport:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def open(self, request, *, timeout):
        self.calls.append((request.get_method(), request.full_url))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        data = json.dumps(value).encode()
        response = io.BytesIO(data)
        response.headers = Message()
        response.headers['Content-Length'] = str(len(data))
        response.status = 200
        return response


def prepared(monkeypatch, tmp_path, *responses):
    monkeypatch.setattr(module, '_require_producer_gone', lambda pid: None)
    monkeypatch.setattr(module.time, 'sleep', lambda duration: None)
    reader = ObservationReader('https://synthetic.invalid', 'pk-test', 'sk-test',
                               project_id='synthetic-project', api_version='v1')
    transport = Transport(responses)
    reader._opener = transport
    scope = module.CanaryTraceRetirement(reader, task_id=TASK, trace_id=TRACE, root_id=ROOT,
                                         producer_pid=42, start_time=1000, end_time=1010,
                                         delete_journal=tmp_path.resolve() / 'delete.json')
    assert not transport.calls  # constructors/imports grant no network or deletion
    return scope, transport


def trace():
    return {'id': TRACE, 'projectId': 'synthetic-project'}


def project():
    return {'data':[{'id':'synthetic-project'}]}


def ack():
    return {'message': 'Trace deleted successfully'}


def missing():
    return HTTPError('https://synthetic.invalid', 404, '', {}, None)


@native_journal
def test_own_trace_deleted_once_and_absence_independently_read(monkeypatch, tmp_path):
    empty = {'data': [], 'meta': {'page': 1, 'limit': 1, 'totalItems': 0, 'totalPages': 0}}
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), trace(), ack(), project(), missing(), empty)
    result = scope.retire()
    assert result['status'] == 'canary_api_retirement_verified'
    assert result['trace_absent'] and result['observations_absent']
    assert not result['backup_or_forensic_erasure']
    assert result['delete_claims'] == result['delete_attempts_current_process'] == 1
    assert [m for m, _ in transport.calls] == ['GET', 'GET', 'DELETE', 'GET', 'GET', 'GET']
    assert transport.calls[2][1] == 'https://synthetic.invalid/api/public/traces/' + TRACE
    with pytest.raises(module.CleanupRefused, match='already_used'):
        scope.retire()
    assert len(transport.calls) == 6


@pytest.mark.parametrize('field,value', [('task_id', 'other'), ('source', 'other'),
    ('platform', 'telegram'), ('capture_mode', 'full'), ('hermes_receipt_root', False)])
def test_non_canary_or_wrong_nonce_never_deletes(monkeypatch, tmp_path, field, value):
    page = root_page()
    page['data'][0]['metadata'][field] = value
    scope, transport = prepared(monkeypatch, tmp_path, page)
    with pytest.raises(module.CleanupRefused):
        scope.retire()
    assert [m for m, _ in transport.calls] == ['GET']


def test_original_producer_still_live_refuses_before_any_request(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path)
    def live(pid):
        raise module.CleanupRefused('producer_not_proven_gone')
    monkeypatch.setattr(module, '_require_producer_gone', live)
    with pytest.raises(module.CleanupRefused, match='producer_not_proven_gone'):
        scope.retire()
    assert transport.calls == []


@native_journal
def test_owned_open_root_from_interrupted_canary_can_be_retired(monkeypatch, tmp_path):
    page = root_page(); page['data'][0]['endTime'] = None
    empty = {'data': [], 'meta': {'page': 1, 'limit': 1, 'totalItems': 0, 'totalPages': 0}}
    scope, _ = prepared(monkeypatch, tmp_path, page, trace(), ack(), project(), missing(), empty)
    assert scope.retire()['status'] == 'canary_api_retirement_verified'


@pytest.mark.parametrize('field,value', [('id', 'd' * 32), ('projectId', 'other')])
def test_wrong_trace_or_project_refuses_delete(monkeypatch, tmp_path, field, value):
    wrong = trace(); wrong[field] = value
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), wrong)
    with pytest.raises(module.CleanupRefused, match='identity_mismatch'):
        scope.retire()
    assert all(m == 'GET' for m, _ in transport.calls)


@native_journal
def test_delete_acknowledgement_is_not_retirement(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), trace(), ack(), project(), *[trace()] * 4)
    assert scope.retire()['status'] == 'canary_deletion_pending'
    assert sum(m == 'DELETE' for m, _ in transport.calls) == 1


@native_journal
def test_ambiguous_write_never_retries_and_raw_error_is_suppressed(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), trace(), OSError('PRIVATE_SENTINEL'))
    with pytest.raises(module.CleanupRefused) as error:
        scope.retire()
    assert 'PRIVATE_SENTINEL' not in str(error.value)
    with pytest.raises(module.CleanupRefused, match='already_used'):
        scope.retire()
    assert sum(m == 'DELETE' for m, _ in transport.calls) == 1


def test_expired_scope_is_inert(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path)
    monkeypatch.setattr(scope._reader, '_clock', lambda: scope._expires)
    with pytest.raises(module.CleanupRefused, match='deadline_changed'):
        scope.retire()
    assert transport.calls == []


@native_journal
def test_trace_missing_but_observations_remain_is_not_retirement(monkeypatch, tmp_path):
    page = root_page()
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), trace(), ack(), project(), missing(), page)
    with pytest.raises(module.CleanupRefused, match='observations_remain'):
        scope.retire()
    assert sum(m == 'DELETE' for m, _ in transport.calls) == 1


@native_journal
def test_durable_claim_prevents_another_object_from_repeating_delete(monkeypatch, tmp_path):
    scope, _ = prepared(monkeypatch, tmp_path, root_page(), trace(), OSError('ambiguous'))
    with pytest.raises(module.CleanupRefused):
        scope.retire()
    fresh, transport = prepared(monkeypatch, tmp_path, root_page(), trace())
    with pytest.raises(module.CleanupRefused, match='delete_already_claimed'):
        fresh.retire()
    assert all(method == 'GET' for method, _ in transport.calls)


@native_journal
def test_pending_deletion_can_be_confirmed_without_another_delete(monkeypatch, tmp_path):
    scope, _ = prepared(monkeypatch, tmp_path, root_page(), trace(), ack(), project(), *[trace()] * 4)
    assert scope.retire()['status'] == 'canary_deletion_pending'
    empty = {'data': [], 'meta': {'page': 1, 'limit': 1, 'totalItems': 0, 'totalPages': 0}}
    fresh, transport = prepared(monkeypatch, tmp_path, project(), missing(), empty)
    recovered = module.CanaryTraceRetirement.from_journal(fresh._reader, task_id=TASK, producer_pid=42,
        start_time=1000,end_time=1010,delete_journal=fresh._journal)
    result = recovered.confirm()
    assert result['status'] == 'canary_api_retirement_verified'
    assert result['delete_claims'] == 1 and result['delete_attempts_current_process'] == 0
    assert all(method == 'GET' for method, _ in transport.calls)


@native_journal
def test_confirmation_requires_exact_private_journal(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path)
    scope._journal.write_text('{}'); scope._journal.chmod(0o600)
    with pytest.raises(module.CleanupRefused, match='delete_journal_changed'):
        scope.confirm()
    assert transport.calls == []


@native_journal
def test_symlinked_journal_parent_cannot_claim_delete(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch, tmp_path, root_page(), trace())
    private = tmp_path / 'owned'; private.mkdir(mode=0o700)
    link = tmp_path / 'link'; link.symlink_to(private, target_is_directory=True)
    scope._journal = link / 'delete.json'
    with pytest.raises(OSError):
        scope.retire()
    assert not (private / 'delete.json').exists()
    assert all(method == 'GET' for method, _ in transport.calls)


@pytest.mark.parametrize('partial', [True, False])
def test_nonce_discovery_can_identify_export_without_a_sealed_receipt(monkeypatch, tmp_path, partial):
    page = root_page(); page['meta']['limit'] = 2
    if partial:
        page['data'][0]['endTime'] = None
    scope, transport = prepared(monkeypatch, tmp_path, page)
    found = module.CanaryTraceRetirement.discover(scope._reader, task_id=TASK, producer_pid=42,
        start_time=1000, end_time=1010, delete_journal=scope._journal)
    assert found._trace == TRACE and found._root == ROOT
    assert all(method == 'GET' for method, _ in transport.calls)
    assert not scope._journal.exists()


@native_journal
def test_recovery_cannot_narrow_the_original_observation_window(monkeypatch, tmp_path):
    scope, _ = prepared(monkeypatch, tmp_path, root_page(), trace(), ack(), project(), *[trace()] * 4)
    assert scope.retire()['status'] == 'canary_deletion_pending'
    reader = ObservationReader('https://synthetic.invalid','pk-test','sk-test',
        project_id='synthetic-project',api_version='v1')
    with pytest.raises(module.CleanupRefused, match='delete_journal_changed'):
        module.CanaryTraceRetirement.from_journal(reader, task_id=TASK,producer_pid=42,
            start_time=1001,end_time=1009,delete_journal=scope._journal)


@native_journal
def test_confirmation_cannot_treat_wrong_project_404_as_retirement(monkeypatch, tmp_path):
    scope, _ = prepared(monkeypatch,tmp_path,root_page(),trace(),ack(),project(),*[trace()]*4)
    assert scope.retire()['status']=='canary_deletion_pending'
    fresh, transport = prepared(monkeypatch,tmp_path,{'data':[{'id':'other-project'}]})
    with pytest.raises(module.CleanupRefused,match='cleanup_project_binding_changed'):
        fresh.confirm()
    assert len(transport.calls)==1 and '/api/public/projects' in transport.calls[0][1]


@pytest.mark.parametrize('same_trace',[True,False])
def test_discovery_allows_only_owned_roots_of_one_trace(monkeypatch,tmp_path,same_trace):
    page=root_page();page['meta'].update(limit=2,totalItems=2)
    other=json.loads(json.dumps(page['data'][0]));other['id']='d'*16
    if not same_trace:
        other['traceId']='e'*32
    page['data'].append(other)
    scope, _=prepared(monkeypatch,tmp_path,page)
    args=dict(task_id=TASK,producer_pid=42,start_time=1000,end_time=1010,delete_journal=scope._journal)
    if same_trace:
        assert module.CanaryTraceRetirement.discover(scope._reader,**args)._trace==TRACE
    else:
        with pytest.raises(module.CleanupRefused,match='canary_discovery_ambiguous'):
            module.CanaryTraceRetirement.discover(scope._reader,**args)


def test_unobserved_nonce_is_not_positive_retirement(monkeypatch, tmp_path):
    empty = {'data': [], 'meta': {'page': 1, 'limit': 2, 'totalItems': 0, 'totalPages': 0}}
    scope, _ = prepared(monkeypatch, tmp_path, empty)
    assert module.CanaryTraceRetirement.discover(scope._reader, task_id=TASK, producer_pid=42,
        start_time=1000, end_time=1010, delete_journal=scope._journal) is None
    assert not scope._journal.exists()


def test_missing_linux_process_authority_refuses_before_any_request(monkeypatch, tmp_path):
    native_guard = module._require_producer_gone
    real_path = module.Path
    scope, transport = prepared(monkeypatch, tmp_path)
    class MissingProcessAuthority:
        def is_file(self):return False
    monkeypatch.setattr(module, '_require_producer_gone', native_guard)
    monkeypatch.setattr(module, 'Path', lambda *parts:
        MissingProcessAuthority() if parts == ('/proc/self/stat',) else real_path(*parts))
    with pytest.raises(module.CleanupRefused, match='producer_not_proven_gone'):
        scope.retire()
    assert transport.calls == []


def test_discovery_and_scope_reconstruction_share_original_budget(monkeypatch, tmp_path):
    page = root_page();page['meta']['limit'] = 2
    initial, transport = prepared(monkeypatch, tmp_path, page)
    expires = initial._expires
    now = [expires - 60]
    monkeypatch.setattr(initial._reader, '_clock', lambda: now[0])
    original_open = transport.open
    def advancing_open(*args, **kwargs):
        response = original_open(*args, **kwargs);now[0] += 2;return response
    transport.open = advancing_open
    found = module.CanaryTraceRetirement.discover(initial._reader,task_id=TASK,producer_pid=42,
        start_time=1000,end_time=1010,delete_journal=initial._journal)
    assert found._budget is initial._budget and found._requests == 1 and found._expires == expires
    now[0] = expires
    another = module.CanaryTraceRetirement(initial._reader,task_id=TASK,trace_id=TRACE,root_id=ROOT,
        producer_pid=42,start_time=1000,end_time=1010,delete_journal=initial._journal)
    with pytest.raises(module.CleanupRefused, match='deadline_changed'):
        another.retire()
    assert len(transport.calls) == 1


@native_journal
def test_discovery_and_final_absence_share_exact_ten_request_ceiling(monkeypatch, tmp_path):
    discovery = root_page();discovery['meta']['limit'] = 2
    empty = {'data': [], 'meta': {'page': 1, 'limit': 1, 'totalItems': 0, 'totalPages': 0}}
    initial, transport = prepared(monkeypatch,tmp_path,discovery,root_page(),trace(),ack(),project(),
        trace(),trace(),trace(),missing(),empty)
    found = module.CanaryTraceRetirement.discover(initial._reader,task_id=TASK,producer_pid=42,
        start_time=1000,end_time=1010,delete_journal=initial._journal)
    assert found.retire()['status'] == 'canary_api_retirement_verified'
    assert found._requests == len(transport.calls) == 10
    with pytest.raises(module.CleanupRefused, match='cleanup_request_limit'):
        found.confirm()
    assert len(transport.calls) == 10


@native_journal
def test_reconstruction_cannot_replenish_read_budget_within_one_pass(monkeypatch, tmp_path):
    scope, transport = prepared(monkeypatch,tmp_path,root_page(),trace(),ack(),project(),*[trace()]*4)
    assert scope.retire()['status'] == 'canary_deletion_pending' and scope._requests == 8
    fresh = module.CanaryTraceRetirement.from_journal(scope._reader,task_id=TASK,producer_pid=42,
        start_time=1000,end_time=1010,delete_journal=scope._journal)
    assert fresh._budget is scope._budget and fresh._requests == 8
    transport.responses.extend([project(),trace(),trace()])
    with pytest.raises(module.CleanupRefused, match='cleanup_request_limit'):
        fresh.confirm()
    assert len(transport.calls) == 10 and sum(m=='DELETE' for m,_ in transport.calls) == 1


@native_journal
@pytest.mark.parametrize('recovery', [False, True])
def test_final_empty_inventory_uses_cleanup_response_cap(monkeypatch,tmp_path,recovery):
    oversized = {'data': [], 'meta': {'page': 1, 'limit': 1, 'totalItems': 0, 'totalPages': 0},
                 'padding': 'x'*300000}
    if recovery:
        original, _ = prepared(monkeypatch,tmp_path,root_page(),trace(),ack(),project(),*[trace()]*4)
        assert original.retire()['status'] == 'canary_deletion_pending'
        scope, transport = prepared(monkeypatch,tmp_path,project(),missing(),oversized)
        recovered = module.CanaryTraceRetirement.from_journal(scope._reader,task_id=TASK,producer_pid=42,
            start_time=1000,end_time=1010,delete_journal=scope._journal)
        operation = recovered.confirm
    else:
        scope, transport = prepared(monkeypatch,tmp_path,root_page(),trace(),ack(),project(),missing(),oversized)
        operation = scope.retire
    with pytest.raises(module.CleanupRefused,match='cleanup_response_limit'):
        operation()
    assert len(transport.calls) == (3 if recovery else 6)
    assert all(method=='GET' for method,_ in transport.calls) if recovery else sum(method=='DELETE' for method,_ in transport.calls)==1


def test_reader_cannot_rebind_a_budget_to_another_nonce(monkeypatch,tmp_path):
    scope, transport = prepared(monkeypatch,tmp_path)
    with pytest.raises(module.CleanupRefused,match='cleanup_budget_binding_changed'):
        module.CanaryTraceRetirement(scope._reader,task_id='telemetry-canary-'+'d'*32,
            trace_id=TRACE,root_id=ROOT,producer_pid=42,start_time=1000,end_time=1010,delete_journal=scope._journal)
    assert not transport.calls


def test_concurrent_budget_reservations_cannot_exceed_ceiling(monkeypatch,tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    scope, transport = prepared(monkeypatch,tmp_path)
    def reserve(_):
        try:scope._budget.reserve(scope._reader,'GET');return True
        except module.CleanupRefused:return False
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(reserve,range(11)))
    assert sum(results)==scope._requests==10 and not transport.calls


def test_cleanup_caps_a_more_permissive_reader_timeout(monkeypatch,tmp_path):
    scope, transport = prepared(monkeypatch,tmp_path,{'ok':True})
    scope._reader._timeout=10
    original_open=transport.open
    def bounded_open(*args,timeout):
        assert 0<timeout<=5
        return original_open(*args,timeout=timeout)
    transport.open=bounded_open
    assert scope._request('GET',scope._reader._url)=={'ok':True}


def test_changed_process_refuses_before_an_inherited_budget_lock(monkeypatch,tmp_path):
    from types import SimpleNamespace
    scope, transport = prepared(monkeypatch,tmp_path)
    class InheritedLock:
        def __enter__(self):pytest.fail('child must reject before entering inherited lock')
        def __exit__(self,*a):pass
    scope._budget.lock=InheritedLock()
    monkeypatch.setattr(module,'os',SimpleNamespace(getpid=lambda:scope._budget.creator+1))
    with pytest.raises(module.CleanupRefused,match='cleanup_owner_or_deadline_changed'):
        scope._budget.reserve(scope._reader,'GET')
    assert not transport.calls
