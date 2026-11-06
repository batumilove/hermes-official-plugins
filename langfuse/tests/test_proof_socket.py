"""Native Linux local transport, private lifecycle and profile context contracts."""
import os
import select
import signal
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from langfuse_plugin.proof_socket import ProofServer, exchange
from langfuse_plugin.proof_wire import ProofClient

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="native SO_PEERCRED/O_PATH required")
KEY = b"synthetic-channel-key".ljust(32, b"!")
BASE = {"profile": "/synthetic/profile", "producer": {"pid": 1, "start_ticks": 2,
        "boot_id": "11111111-1111-1111-1111-111111111111"}, "trace_id": "a" * 32,
        "turn_sha256": "b" * 64, "receipt_sha256": "c" * 64}
FULL = dict(BASE, registration_sha256="d" * 64)


def handler(operation, binding):
    return {"binding": FULL, "envelope": None if operation == "describe" else dict(FULL, synthetic=True)}


@pytest.fixture
def paths():
    # AF_UNIX has a native 107-byte path bound; deep CI workspaces exceed it.
    with tempfile.TemporaryDirectory(prefix="hp-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        key, sock = root / "key", root / "socket"
        key.write_bytes(KEY)
        key.chmod(0o600)
        yield key, sock


def serve(paths, callback=handler, enabled=lambda: True):
    key, path = paths
    return ProofServer(str(path), str(key), profile=BASE["profile"], producer=BASE["producer"],
                       handler=callback, enabled=enabled)


def test_real_socket_describe_transfer_and_owned_handle_release(paths):
    server = serve(paths)
    client = ProofClient(KEY)
    key, path = paths
    try:
        assert path.stat().st_mode & 0o777 == 0o600
        request = client.begin("describe", BASE)
        ready = client.accept(exchange(str(path), request))
        assert ready.status == "ready" and ready.binding == FULL and ready.envelope is None
        request = client.begin("transfer", ready.binding)
        assert client.accept(exchange(str(path), request)).status == "transferred"
        assert client.accept(exchange(str(path), request)) is None
    finally:
        assert server.close()
    assert path.exists() and key.read_bytes() == KEY
    with pytest.raises((OSError, ValueError)):
        exchange(str(path), client.begin("describe", BASE))


def test_worker_has_own_profile_no_launch_secrets_or_turn(paths):
    from agent.secret_scope import current_secret_scope, set_secret_scope
    from hermes_constants import get_hermes_home
    from hermes_cli.plugins_turn_boundary import _CURRENT

    observed = []
    def inspect(operation, binding):
        observed.append((str(get_hermes_home()), current_secret_scope(), _CURRENT.get()))
        return handler(operation, binding)
    token = set_secret_scope({"SYNTHETIC_PRIVATE_SENTINEL": "never inherit"}, profile_home="/other")
    server = serve(paths, inspect)
    try:
        client = ProofClient(KEY)
        assert client.accept(exchange(str(paths[1]), client.begin("describe", BASE)))
        assert observed == [(BASE["profile"], {}, None)]
    finally:
        server.close()
        from agent.secret_scope import reset_secret_scope
        reset_secret_scope(token)


def test_existing_socket_is_preserved(paths):
    server = serve(paths)
    original = paths[1].stat().st_ino
    try:
        with pytest.raises(OSError):
            serve(paths)
        assert paths[1].stat().st_ino == original
        client = ProofClient(KEY)
        assert client.accept(exchange(str(paths[1]), client.begin("describe", BASE)))
    finally:
        server.close()


@pytest.mark.parametrize("frame", [b"", struct.pack("!I", 8193),
                                    struct.pack("!I", 10) + b"short",
                                    struct.pack("!I", 2) + b"{}extra"])
def test_malformed_frame_never_calls_handler(paths, frame):
    calls = []
    def capture(operation, binding):
        calls.append(binding)
        return handler(operation, binding)
    server = serve(paths, capture)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(str(paths[1]))
            sock.sendall(frame)
            sock.shutdown(socket.SHUT_WR)
            try:
                assert sock.recv(1) == b""
            except ConnectionResetError:
                pass  # rejecting unread trailing bytes may reset instead of returning EOF
        assert calls == []
    finally:
        server.close()


def test_key_change_revokes_worker_without_deleting_key(paths):
    server = serve(paths)
    paths[0].write_bytes(b"other-key".ljust(32, b"!"))
    server._thread.join(timeout=2)
    assert not server.active
    assert server.close()
    assert paths[0].read_bytes() != KEY


def test_config_revoked_inside_handler_discards_reply(paths):
    enabled = [True]
    def revoke(operation, binding):
        enabled[0] = False
        return handler(operation, binding)
    server = serve(paths, revoke, lambda: enabled[0])
    try:
        client = ProofClient(KEY)
        assert client.accept(exchange(str(paths[1]), client.begin("describe", BASE))) is None
        server._thread.join(timeout=2)
        assert not server.active
    finally:
        server.close()


def test_replacement_namespace_is_not_unlinked(paths):
    server = serve(paths)
    path = paths[1]
    path.unlink()
    path.write_bytes(b"replacement owner")
    path.chmod(0o600)
    assert server.close()
    assert path.read_bytes() == b"replacement owner"


def test_close_during_handler_never_emits_authorized_reply(paths):
    entered, release, authority_closed = threading.Event(), threading.Event(), threading.Event()
    def hold(operation, binding):
        entered.set()
        assert release.wait(timeout=5)
        return handler(operation, binding)
    server = serve(paths, hold)
    original_close = server._authority.close
    def close_authority():
        original_close()
        authority_closed.set()
    server._authority.close = close_authority
    result = []
    def request():
        try:
            client = ProofClient(KEY)
            result.append(client.accept(exchange(str(paths[1]), client.begin("describe", BASE))))
        except (OSError, ValueError):
            result.append(None)
    requester = threading.Thread(target=request)
    requester.start()
    assert entered.wait(timeout=5)
    closer = threading.Thread(target=server.close)
    closer.start()
    assert authority_closed.wait(timeout=5)
    release.set()
    closer.join(timeout=5)
    requester.join(timeout=5)
    assert not closer.is_alive() and not requester.is_alive()
    assert result == [None] and paths[1].exists() and not server.active


def test_release_preserves_replacement_even_after_valid_identity_check(paths):
    from langfuse_plugin.proof_paths import PrivateSocket
    path = paths[1]
    owned = PrivateSocket(str(path))
    assert owned.owned()
    path.rename(path.parent / "original-socket")
    path.write_bytes(b"synthetic replacement owner")
    path.chmod(0o600)
    owned.release()
    assert path.read_bytes() == b"synthetic replacement owner"
    assert (path.parent / "original-socket").exists()


def test_fork_copy_closes_without_parent_lock_or_socket_shutdown(paths):
    server = serve(paths)
    read_fd, write_fd = os.pipe()
    child = None
    try:
        with server._connection_lock, server._close_lock:
            child = os.fork()
            if child == 0:
                try:
                    os.close(read_fd)
                    server.close()
                    os.write(write_fd, b"closed")
                finally:
                    os._exit(0)
            os.close(write_fd)
            write_fd = None
            ready, _, _ = select.select([read_fd], [], [], 3)
            assert ready and os.read(read_fd, 6) == b"closed"
        _, status = os.waitpid(child, 0)
        child = None
        assert os.waitstatus_to_exitcode(status) == 0
        client = ProofClient(KEY)
        assert client.accept(exchange(str(paths[1]), client.begin("describe", BASE)))
    finally:
        if child:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        server.close()
