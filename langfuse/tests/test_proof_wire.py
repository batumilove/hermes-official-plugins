"""Synthetic request-bound authority; no sockets, live producer or backend claims."""
import json
from dataclasses import FrozenInstanceError

import pytest

from langfuse_plugin.proof_wire import ProofAuthority, ProofClient


KEY = b"synthetic-key".ljust(32, b"!")
NOW = 1793980000.0
BASE = {"profile": "synthetic-profile", "producer": {"pid": 42, "start_ticks": 123,
        "boot_id": "11111111-1111-1111-1111-111111111111"}, "trace_id": "a" * 32,
        "turn_sha256": "b" * 64, "receipt_sha256": "c" * 64}
BINDING = dict(BASE, registration_sha256="d" * 64)


def world(handler=None, *, valid=lambda: True):
    calls = []

    def serve(operation, binding):
        calls.append((operation, binding))
        if handler is not None:
            return handler(operation, binding)
        return {"binding": dict(BINDING), "envelope": None if operation == "describe"
                else dict(BINDING, synthetic=True)}

    server = ProofAuthority(KEY, profile=BASE["profile"], producer=BASE["producer"],
                            handler=serve, key_valid=valid, clock=lambda: NOW)
    client = ProofClient(KEY, clock=lambda: NOW)
    return server, client, calls


def test_describe_then_transfer_requires_new_request_and_strict_binding():
    server, client, calls = world()
    first = client.begin("describe", BASE)
    reply = client.accept(server.process(first))
    assert reply.status == "ready" and reply.binding == BINDING and reply.envelope is None
    second = client.begin("transfer", reply.binding)
    assert json.loads(first)["request_id"] != json.loads(second)["request_id"]
    result = client.accept(server.process(second))
    assert result.status == "transferred"
    assert json.loads(result.envelope)["trace_id"] == BASE["trace_id"]
    assert [op for op, _ in calls] == ["describe", "transfer"]
    copy = result.binding
    copy["profile"] = "changed"
    assert result.binding["profile"] == BASE["profile"]
    with pytest.raises(FrozenInstanceError):
        result.status = "delivered"


def test_replayed_request_and_reply_cannot_be_accepted():
    server, client, calls = world()
    request = client.begin("describe", BASE)
    reply = server.process(request)
    assert client.accept(reply).status == "ready"
    assert client.accept(reply) is None
    newer = client.begin("describe", BASE)
    assert client.accept(reply) is None
    assert server.process(request) != reply
    assert len(calls) == 1
    # Failed acceptance consumed the newer pending request, not a retry allowance.
    assert client.accept(server.process(newer)) is None


@pytest.mark.parametrize("field, value", [("profile", "other"), ("trace_id", "e" * 32),
                                          ("receipt_sha256", "e" * 64)])
def test_handler_cannot_substitute_binding(field, value):
    def bad(operation, binding):
        return {"binding": dict(BINDING, **{field: value}), "envelope": None}
    server, client, _ = world(bad)
    assert client.accept(server.process(client.begin("describe", BASE))) is None


def test_wrong_profile_and_producer_never_reach_handler():
    for change in ({"profile": "other"}, {"producer": dict(BASE["producer"], pid=43)}):
        server, client, calls = world()
        assert client.accept(server.process(client.begin("describe", dict(BASE, **change)))) is None
        assert calls == []


def test_wrong_key_malformed_and_oversize_never_reach_handler():
    server, client, calls = world()
    other = ProofClient(b"x" * 32, clock=lambda: NOW)
    for wire in [other.begin("describe", BASE), b"[]", b"not json", b"x" * 8193]:
        server.process(wire)
    assert calls == []
    assert client.accept(b"{}") is None


def test_key_or_lifecycle_invalidation_during_handler_is_permanent():
    valid = [True]

    def invalidate(operation, binding):
        valid[0] = False
        return {"binding": BINDING, "envelope": None}

    server, client, _ = world(invalidate, valid=lambda: valid[0])
    assert client.accept(server.process(client.begin("describe", BASE))) is None
    valid[0] = True
    assert client.accept(server.process(client.begin("describe", BASE))) is None


def test_pending_request_and_lifetime_cap_are_bounded():
    server, client, calls = world()
    pending = client.begin("describe", BASE)
    with pytest.raises(RuntimeError):
        client.begin("describe", BASE)
    assert client.accept(server.process(pending)) is not None
    for _ in range(255):
        assert client.accept(server.process(client.begin("describe", BASE))) is not None
    with pytest.raises(RuntimeError):
        client.begin("describe", BASE)
    assert len(calls) == 256


def test_stale_request_and_stale_reply_fail_closed():
    server, client, calls = world()
    old = ProofClient(KEY, clock=lambda: NOW - 31)
    assert old.accept(server.process(old.begin("describe", BASE))) is None
    assert calls == []
    request = client.begin("describe", BASE)
    response = server.process(request)
    client._clock = lambda: NOW + 31
    assert client.accept(response) is None


def test_handler_errors_are_content_free():
    def fail(operation, binding):
        raise RuntimeError("SENSITIVE_SENTINEL")
    server, client, _ = world(fail)
    response = server.process(client.begin("describe", BASE))
    assert b"SENSITIVE_SENTINEL" not in response
    assert client.accept(response) is None


def test_consumer_close_observed_during_accept_refuses_reply():
    server, client, _ = world()
    response = server.process(client.begin("describe", BASE))

    def close_during_clock_read():
        client.close()
        return NOW

    client._clock = close_during_clock_read
    assert client.accept(response) is None


def test_authority_close_observed_inside_final_key_guard_refuses_reply():
    calls = [0]
    server, client, handled = world()

    def guard():
        calls[0] += 1
        if calls[0] == 2:
            server.close()
        return True

    server._key_valid = guard
    assert client.accept(server.process(client.begin("describe", BASE))) is None
    assert len(handled) == 1
