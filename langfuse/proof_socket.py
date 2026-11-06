"""Opt-in Linux local proof transport. No provisioning, TCP listener or backend polling."""
from __future__ import annotations

import contextvars
import os
import socket
import stat
import struct
import threading
import time

from .delivery_receipts import _private_directory
from .proof_paths import PrivateKey, PrivateSocket, _path
from .proof_wire import MAX_REQUEST, MAX_RESPONSE, ProofAuthority


def _peer(sock):
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _read(sock, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("proof frame deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ValueError("incomplete proof frame")
        result.extend(chunk)
    return bytes(result)


def _receive(sock, maximum, deadline):
    size = struct.unpack("!I", _read(sock, 4, deadline))[0]
    if not 0 < size <= maximum:
        raise ValueError("proof frame bound")
    payload = _read(sock, size, deadline)
    # Each connection carries exactly one frame; EOF is mandatory, not a retry.
    sock.settimeout(max(0.001, deadline - time.monotonic()))
    if sock.recv(1):
        raise ValueError("trailing proof bytes")
    return payload


def _send(sock, payload, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("proof frame deadline")
    sock.settimeout(remaining)
    sock.sendall(struct.pack("!I", len(payload)) + payload)
    sock.shutdown(socket.SHUT_WR)


def _profile_thread(profile, target):
    # Start outside the first turn's context: retaining that ContextVar would
    # retain its boundary, and inherited launch secrets could cross profiles.
    def build():
        from agent.memory_provider import spawn_context_thread
        from agent.secret_scope import set_multiplex_context, set_secret_scope
        from hermes_constants import set_hermes_home_override
        set_hermes_home_override(profile)
        set_secret_scope({}, profile_home=profile)
        set_multiplex_context(True)
        return spawn_context_thread(target, name="langfuse-proof-channel", daemon=True)
    return contextvars.Context().run(build)


class ProofServer:
    """One bounded worker; authority dies before shutdown. Never retire socket paths."""

    def __init__(self, socket_path, key_path, *, profile, producer, handler, enabled):
        self.pid, self._stop = os.getpid(), threading.Event()
        self._connection_lock, self._connection = threading.Lock(), None
        self._close_lock = threading.Lock()
        self._thread = self._key = self._socket = self._authority = None
        self._enabled = enabled
        try:
            self._key = PrivateKey(key_path)
            self._socket = PrivateSocket(socket_path)
            self._authority = ProofAuthority(self._key.value, profile=profile, producer=producer,
                                            handler=handler, key_valid=self._valid)
            self._thread = _profile_thread(profile, self._serve)
            self._thread.start()
        except BaseException:
            self.close()
            raise

    @property
    def key(self):
        return self._key.value

    @property
    def active(self):
        return (os.getpid() == self.pid and not self._stop.is_set()
                and self._authority is not None and self._authority.active
                and self._thread is not None and self._thread.is_alive())

    def _valid(self):
        return (os.getpid() == self.pid and not self._stop.is_set()
                and self._enabled() is True and self._socket.owned() and self._key.valid())

    def _serve(self):
        try:
            while not self._stop.is_set() and self._authority.active:
                if not self._valid():
                    break
                try:
                    connection, _ = self._socket.socket.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with connection:
                    with self._connection_lock:
                        self._connection = connection
                    try:
                        if self._stop.is_set() or _peer(connection) != os.getuid():
                            continue
                        deadline = time.monotonic() + 1.0
                        wire = _receive(connection, MAX_REQUEST, deadline)
                        response = self._authority.process(wire)
                        if not self._stop.is_set():
                            _send(connection, response, deadline)
                    except (OSError, ValueError):
                        pass  # no unauthenticated diagnostics on the proof socket
                    finally:
                        with self._connection_lock:
                            self._connection = None
        except Exception:
            pass  # configuration/key failures revoke authority without private error output
        finally:
            self._authority.close()
            self._stop.set()

    def close(self):
        if self._authority is not None:
            self._authority.close()
        if os.getpid() != self.pid:
            # Never shutdown a parent's shared socket description after fork.
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            if self._socket is not None:
                self._socket.release()
            if self._key is not None:
                self._key.close()
            return False
        with self._close_lock:
            return self._finish_close()

    def _finish_close(self):
        self._stop.set()
        if self._socket is not None:
            self._socket.stop_accepting()
        with self._connection_lock:
            if self._connection is not None:
                try:
                    self._connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        thread = self._thread
        if thread is not None and thread.ident is not None:
            if thread is threading.current_thread():
                return False
            thread.join(timeout=2.0)
            if thread.is_alive():
                return False  # preserve inode/key descriptors until termination is proved
        if self._socket is not None:
            self._socket.release()
        if self._key is not None:
            self._key.close()
        return True  # worker terminated and handles closed; pathname deliberately retained


def exchange(path, request):
    """One local request, no retries; callers authenticate the reply with ProofClient."""
    if not hasattr(socket, "SO_PEERCRED") or not isinstance(request, bytes) or not 0 < len(request) <= MAX_REQUEST:
        raise ValueError("native bounded proof request required")
    path = _path(path)
    parent = _private_directory(str(path.parent))
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600):
            raise ValueError("private proof socket required")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            deadline = time.monotonic() + 2.0
            sock.settimeout(2.0)
            sock.connect(str(path))
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or _peer(sock) != os.getuid()):
                raise ValueError("proof socket owner changed")
            _send(sock, request, deadline)
            return _receive(sock, MAX_RESPONSE, deadline)
    finally:
        os.close(parent)
