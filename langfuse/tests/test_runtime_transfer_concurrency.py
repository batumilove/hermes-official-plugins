"""Portable adapter scheduling tests; storage stalls are controlled by events."""
import threading
from types import SimpleNamespace

import pytest

from langfuse_plugin.receipt_runtime import ReceiptRuntime


@pytest.mark.parametrize('change', ['none', 'expiry', 'replacement', 'disabled', 'closed'])
def test_stalled_transfer_does_not_hold_runtime_mutex_and_revalidates(tmp_path, change):
    now = [0.0]
    active = [True]
    directory = str(tmp_path)
    settings = {'enabled': True, 'directory': directory}
    context = SimpleNamespace(_manager=SimpleNamespace(scope_key='profile'),
        get_config=lambda key, default=None: settings,
        on_unload=lambda fn: SimpleNamespace(active=True))
    runtime = ReceiptRuntime(context, clock=lambda: now[0])
    runtime._channel_spec = (directory, 'socket', 'key')
    runtime._channel_enabled = lambda: active[0] and not runtime.closed
    binding = {'profile': 'profile', 'producer': {'pid': 1},
               'turn_sha256': 'turn', 'trace_id': 'trace'}
    entered, release, probe_done = threading.Event(), threading.Event(), threading.Event()
    result, errors = [], []

    def issue(trace):
        entered.set()
        if not release.wait(5):
            raise RuntimeError('test release missing')
        return b'synthetic transfer'

    collector = SimpleNamespace(profile='profile', producer={'pid': 1}, turn_sha256='turn',
        turn_id='turn', collect=lambda **kw: {'trace': {'status': 'collected'}},
        expected_binding=lambda trace: dict(binding), issue_transfer=issue)
    key = (directory, object())
    runtime.turns[key] = (now[0], collector)

    def transfer():
        try:
            result.append(runtime._proof_handler('transfer', binding))
        except BaseException as exc:
            errors.append(exc)

    def probe():
        try:
            assert runtime.collect('absent') == {'status': 'unverified'}
            with runtime.lock:
                if change == 'expiry':
                    now[0] = 301
                elif change == 'replacement':
                    runtime.turns[key] = (now[0], collector)
                elif change == 'disabled':
                    active[0] = False
            if change == 'closed':
                runtime.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            probe_done.set()

    worker = threading.Thread(target=transfer)
    other = threading.Thread(target=probe)
    worker.start()
    try:
        assert entered.wait(2)
        other.start()
        finished_before_release = probe_done.wait(0.5)
    finally:
        release.set()
        worker.join(2)
        if other.ident is not None:
            other.join(2)
    assert finished_before_release, 'proof I/O held the runtime mutex'
    assert not worker.is_alive() and not other.is_alive() and not errors
    assert result == ([{'binding': binding, 'envelope': b'synthetic transfer'}]
                      if change == 'none' else [None])


@pytest.mark.parametrize('change', ['none', 'expiry', 'replacement', 'closed'])
def test_same_collector_admission_cannot_restore_global_convoy(tmp_path, monkeypatch, change):
    from hermes_cli import plugins_turn_boundary as boundary
    now = [0.0]
    directory = str(tmp_path)
    context = SimpleNamespace(_manager=SimpleNamespace(scope_key='profile'),
        get_config=lambda *args: {'enabled': True, 'directory': directory},
        on_unload=lambda fn: SimpleNamespace(active=True))
    runtime = ReceiptRuntime(context, clock=lambda: now[0])
    runtime._ensure_channel = lambda directory: None
    class Scope:
        turn_id = 'turn'

    scope = Scope()
    key = (directory, scope)
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    invalidated, admitted, errors = [], [], []
    receipt = SimpleNamespace(invalidate=lambda: invalidated.append(True))

    def stalled_open(*args):
        entered.set()
        assert release.wait(5)
        return receipt

    collector = SimpleNamespace(turn_id='turn', profile='profile', open_trace=stalled_open,
                                retain=lambda trace: object())
    item = (0.0, collector)
    runtime.turns[key] = item

    def admit():
        token = boundary._CURRENT.set(scope)
        try:
            admitted.append(runtime.open_trace('trace', 'root', 'turn'))
        except BaseException as exc:
            errors.append(exc)
        finally:
            boundary._CURRENT.reset(token)

    def other_turn():
        try:
            assert runtime.collect('absent') == {'status': 'unverified'}
            with runtime.lock:
                if change == 'expiry':
                    now[0] = 301
                elif change == 'replacement':
                    runtime.turns[key] = (0.0, collector)
            if change == 'closed':
                runtime.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    first, second = threading.Thread(target=admit), threading.Thread(target=other_turn)
    first.start()
    try:
        assert entered.wait(2)
        second.start()
        progressed = done.wait(0.5)
    finally:
        release.set()
        first.join(2)
        if second.ident is not None:
            second.join(2)
    assert progressed and not first.is_alive() and not second.is_alive() and not errors
    assert admitted == ([receipt] if change == 'none' else [None])
    assert invalidated == ([] if change == 'none' else [True])
