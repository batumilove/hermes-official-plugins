"""Real retained Receipt through native socket/authentication to independent offline HTTP readback."""
import importlib.util
import io
import json
import sys
import tempfile
import time
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path

import pytest

if importlib.util.find_spec("hermes_cli.plugins_turn_boundary") is None:
    pytest.skip("optional host turn-evidence API absent; required by pinned-core CI", allow_module_level=True)

from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from hermes_cli.plugins_turn_boundary import reserve_current_activity, turn_boundary
from langfuse_plugin.backend_readback import ObservationReader
from langfuse_plugin.delivery_receipts import _digest, producer_identity, read_receipt
from langfuse_plugin.delivery_verification import DeliveryVerifier
from langfuse_plugin.proof_socket import exchange
from langfuse_plugin.proof_wire import ProofClient
from langfuse_plugin.live_delivery import LiveDeliveryAttempt
from langfuse_plugin.receipt_runtime import ReceiptRuntime

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="native producer/socket identity required")
KEY = b"synthetic-channel-key".ljust(32, b"!")
TRACE, ROOT, TURN = "a" * 32, "b" * 16, "synthetic-turn"


class Backend:
    def __init__(self):
        self.calls, self.rows, self.fail = 0, [], False

    def open(self, request, *, timeout):
        self.calls += 1
        if self.fail:
            raise TimeoutError("synthetic private exception")
        payload = json.dumps({"data": self.rows, "meta": {}}).encode()
        result = io.BytesIO(payload)
        result.status, result.headers = 200, Message()
        result.headers["Content-Length"] = str(len(payload))
        return result


@pytest.fixture
def world(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory(prefix="hl-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        receipts, proofs = root / "receipts", root / "proofs"
        receipts.mkdir(mode=0o700)
        proofs.mkdir(mode=0o700)
        key, path = proofs / "key", proofs / "socket"
        key.write_bytes(KEY)
        key.chmod(0o600)
        manager = PluginManager(scope_key=str(tmp_path.resolve()))
        context = PluginContext(PluginManifest(name="langfuse"), manager)
        settings = {"enabled": True, "directory": str(receipts), "proof_channel": {
            "enabled": True, "socket": str(path), "key_file": str(key)}}
        monkeypatch.setattr(context, "get_config", lambda key, default=None: settings)
        runtime = ReceiptRuntime(context)
        backend = Backend()
        reader = ObservationReader("https://synthetic.invalid", "pk-synthetic", "sk-synthetic",
                                   project_id="synthetic-project")
        reader._opener = backend
        yield runtime, manager, settings, path, backend, DeliveryVerifier(KEY, reader)
        runtime.close()


def seal(world, *, reason="normal", queued=False, fail=False):
    runtime, manager, settings, _, backend, _ = world
    start = time.time()
    with turn_boundary(manager, TURN) as scope:
        receipt = runtime.open_trace(TRACE, ROOT, TURN)
        assert receipt is not None
        activity = reserve_current_activity() if queued else None
        receipt.ended(ROOT)
        assert receipt.finish(reason)
        if fail:
            scope.fail()
    end = time.time()
    stamp = lambda value: datetime.fromtimestamp(value, UTC).isoformat()
    backend.rows = [{"id": ROOT, "traceId": TRACE, "projectId": "synthetic-project",
                     "parentObservationId": None, "startTime": stamp(start), "endTime": stamp(end)}]
    snapshot = read_receipt(settings["directory"], TRACE)
    # Pins originate in the owner's producer observation and immutable local Receipt,
    # not in the response or its inner envelope. Registration is authenticated discovery.
    base = {"profile": manager.scope_key, "producer": producer_identity(), "trace_id": TRACE,
            "turn_sha256": snapshot["turn_sha256"], "receipt_sha256": _digest(snapshot)}
    return receipt, base, activity


def describe(world, base, client):
    return client.accept(exchange(str(world[3]), client.begin("describe", base)))


def transfer(world, binding, client):
    return client.accept(exchange(str(world[3]), client.begin("transfer", binding)))


def test_original_receipt_to_backend_and_no_replayed_acceptance(world):
    _, base, _ = seal(world)
    client = ProofClient(KEY)
    ready = describe(world, base, client)
    assert ready.status == "ready" and ready.envelope is None
    sent = transfer(world, ready.binding, client)
    assert sent.status == "transferred"
    result = world[5].verify(sent.envelope, expected_binding=ready.binding)
    assert result.verdict == "captured_inventory_delivered"
    assert result.expected_count == result.observed_count == 1 and world[4].calls == 1
    assert world[5].verify(sent.envelope, expected_binding=ready.binding).verdict == "unverified"
    assert transfer(world, ready.binding, client) is None and world[4].calls == 1


def test_pending_callback_cannot_transfer_until_actual_release(world):
    _, base, activity = seal(world, queued=True)
    client = ProofClient(KEY)
    assert describe(world, base, client) is None
    activity.leave()
    ready = describe(world, base, client)
    assert transfer(world, ready.binding, client).status == "transferred"


@pytest.mark.parametrize("case", ["late", "shutdown", "cancel", "registration", "abandoned"])
def test_nonterminal_or_changed_authority_never_reaches_backend(world, case):
    receipt, base, _ = seal(world, reason="shutdown" if case == "shutdown" else "normal",
                            fail=case == "cancel")
    client = ProofClient(KEY)
    ready = describe(world, base, client)
    if case in {"shutdown", "cancel"}:
        # A collected report may carry a false terminal proof; it cannot be transferred.
        assert ready is None or transfer(world, ready.binding, client) is None
    else:
        assert ready is not None
        if case == "late":
            receipt.invalidate()
        elif case == "registration":
            world[0].context.register_hook("synthetic_changed_hook", lambda payload: None)
        else:
            world[0].context._load_abandoned = True
        assert transfer(world, ready.binding, client) is None
    assert world[4].calls == 0


@pytest.mark.parametrize("case", ["missing", "wrong_parent", "timeout"])
def test_backend_failure_is_not_delivery_or_retry_allowance(world, case):
    _, base, _ = seal(world)
    if case == "missing":
        world[4].rows = []
    elif case == "wrong_parent":
        world[4].rows[0]["parentObservationId"] = "c" * 16
    else:
        world[4].fail = True
    client = ProofClient(KEY)
    ready = describe(world, base, client)
    sent = transfer(world, ready.binding, client)
    result = world[5].verify(sent.envelope, expected_binding=ready.binding)
    assert result.verdict in {"mismatch", "unverified"}
    assert world[5].verify(sent.envelope, expected_binding=ready.binding).verdict == "unverified"
    assert world[4].calls == 1


def test_unload_revokes_listener_and_preserves_receipts(world):
    _, base, _ = seal(world)
    runtime = world[0]
    assert describe(world, base, ProofClient(KEY))
    runtime._cleanup_handle.dispose()
    assert runtime.closed and not runtime.channel.active and world[3].exists()
    assert read_receipt(world[2]["directory"], TRACE)["trace_id"] == TRACE


def test_no_cleanup_capability_cannot_start_channel(world):
    runtime, manager, settings, path, _, _ = world
    from types import SimpleNamespace
    bare = SimpleNamespace(get_config=lambda *args: settings, _manager=manager)
    other = ReceiptRuntime(bare)
    with turn_boundary(manager, TURN):
        assert other.open_trace(TRACE, ROOT, TURN) is None
    assert not path.exists() and runtime.channel is None


def test_proof_state_nested_under_receipts_is_refused_before_listener(world):
    runtime, _, settings, path, _, _ = world
    nested = Path(settings["directory"]) / "nested"
    settings["proof_channel"]["socket"] = str(nested / "socket")
    with pytest.raises(ValueError, match="separate private directory"):
        runtime._proof_config(settings["directory"])
    assert runtime.channel is None and not path.exists() and not nested.exists()


def test_same_turn_text_is_ambiguous_and_retention_expires(world):
    _, base, _ = seal(world)
    runtime, manager = world[:2]
    with turn_boundary(manager, TURN):
        assert runtime.open_trace("c" * 32, ROOT, TURN) is not None
    assert describe(world, base, ProofClient(KEY)) is None
    runtime.clock = lambda: time.monotonic() + 301
    assert describe(world, base, ProofClient(KEY)) is None
    assert not runtime.turns


def attempt(world):
    reader = world[5]._reader
    return LiveDeliveryAttempt(socket_path=str(world[3]),
                               key_file=str(world[3].parent / "key"), reader=reader)


def test_single_selected_attempt_requests_fresh_proof_and_returns_fixed_counts(world):
    _, base, _ = seal(world)
    with attempt(world) as consumer:
        result = consumer.verify(expected_binding=base)
        assert result.verdict == "captured_inventory_delivered"
        assert consumer.verify(expected_binding=base).reason == "attempt_consumed"
    assert consumer.verify(expected_binding=base).reason == "attempt_closed"
    assert world[4].calls == 1


def test_attempt_close_during_backend_read_discards_positive_result(world):
    _, base, _ = seal(world)
    with attempt(world) as consumer:
        original = world[4].open
        def close_during_read(*args, **kwargs):
            result = original(*args, **kwargs)
            consumer.close()
            return result
        world[4].open = close_during_read
        assert consumer.verify(expected_binding=base).verdict == "unverified"
        assert world[4].calls == 1


def test_attempt_key_change_before_request_never_queries_backend(world):
    _, base, _ = seal(world)
    with attempt(world) as consumer:
        (world[3].parent / "key").write_bytes(b"changed".ljust(32, b"!"))
        assert consumer.verify(expected_binding=base).verdict == "unverified"
        assert world[4].calls == 0
