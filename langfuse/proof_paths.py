"""Read-only key custody and owned socket handles; pathname retirement belongs to the owner."""
from __future__ import annotations

import hashlib
import os
import socket
import stat
import time
from pathlib import Path

from .delivery_receipts import _private_directory

_MAX_KEY_AGE = 86400.0


def _path(value):
    if not isinstance(value, str) or not os.path.isabs(value):
        raise ValueError("absolute private path required")
    path = Path(value)
    if ".." in path.parts or not path.name:
        raise ValueError("invalid private path")
    return path


def _fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _regular_key(st):
    return (stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size == 32)


class PrivateKey:
    """Pin one existing file and its namespace; observed change/expiry is permanent.

    The server owns this lease. It closes it after its worker has stopped, so a
    live key read never races descriptor reuse. No secure heap-erasure claim is
    made for Python bytes or HMAC's internal copies.
    """

    def __init__(self, path, *, clock=time.time, monotonic=time.monotonic):
        self.path = _path(path)
        self._pid, self._dead = os.getpid(), False
        self._parent, self._fd = None, None
        self._clock, self._monotonic = clock, monotonic
        try:
            self._parent = _private_directory(str(self.path.parent))
            st = os.fstat(self._parent)
            self._parent_identity = (st.st_dev, st.st_ino)
            self._fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=self._parent)
            before = os.fstat(self._fd)
            if not _regular_key(before):
                raise ValueError("invalid private key file")
            value = os.pread(self._fd, 33, 0)
            after = os.fstat(self._fd)
            age = self._clock() - after.st_mtime
            if (len(value) != 32 or _fingerprint(before) != _fingerprint(after)
                    or not -5 <= age <= _MAX_KEY_AGE):
                raise ValueError("invalid or expired private key")
            self.value = value
            self._digest = hashlib.sha256(value).digest()
            self._identity = _fingerprint(after)
            self._deadline = self._monotonic() + _MAX_KEY_AGE - max(0, age)
        except BaseException:
            self.close()
            raise

    def in_lifetime(self):
        if (self._dead or os.getpid() != self._pid
                or self._monotonic() >= self._deadline):
            self._dead = True
            return False
        return True

    def valid(self):
        if not self.in_lifetime():
            return False
        parent = None
        try:
            parent = _private_directory(str(self.path.parent))
            st = os.fstat(parent)
            if (st.st_dev, st.st_ino) != self._parent_identity:
                raise ValueError("key namespace changed")
            named = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            before = os.fstat(self._fd)
            value = os.pread(self._fd, 33, 0)
            after = os.fstat(self._fd)
            age = self._clock() - after.st_mtime
            if (_regular_key(named) and _fingerprint(named) == self._identity
                    and _fingerprint(before) == self._identity == _fingerprint(after)
                    and hashlib.sha256(value).digest() == self._digest
                    and -5 <= age <= _MAX_KEY_AGE):
                return self.in_lifetime()
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        finally:
            if parent is not None:
                os.close(parent)
        self._dead = True
        return False

    def close(self):
        self._dead = True
        for attribute in ("_fd", "_parent"):
            fd = self.__dict__.pop(attribute, None)
            if fd is not None:
                os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class PrivateSocket:
    """One Linux pathname socket; refuse existing paths and retain its inode pin until release."""

    def __init__(self, path):
        self.path = _path(path)
        if not hasattr(os, "O_PATH") or not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("native Linux proof socket required")
        if len(os.fsencode(path)) > 107:
            raise ValueError("proof socket path exceeds native bound")
        self.pid = os.getpid()
        self.parent, self.pin, self.socket = None, None, None
        self.identity = None
        try:
            self.parent = _private_directory(str(self.path.parent))
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.bind(str(self.path))  # no unlink/replacement of an existing owner
            self.pin = os.open(self.path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=self.parent)
            st = os.fstat(self.pin)
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
                raise ValueError("socket ownership unavailable")
            self.identity = (st.st_dev, st.st_ino)
            os.chmod(self.path.name, 0o600, dir_fd=self.parent, follow_symlinks=False)
            self.socket.settimeout(0.25)
            self.socket.listen(2)
        except BaseException:
            self.release()
            raise

    def owned(self):
        if os.getpid() != self.pid or getattr(self, "parent", None) is None or self.identity is None:
            return False
        current = None
        try:
            current = _private_directory(str(self.path.parent))
            original, observed = os.fstat(self.parent), os.fstat(current)
            if (original.st_dev, original.st_ino) != (observed.st_dev, observed.st_ino):
                return False
            st = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
            return (stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid()
                    and stat.S_IMODE(st.st_mode) == 0o600
                    and (st.st_dev, st.st_ino) == self.identity)
        except (OSError, ValueError):
            return False
        finally:
            if current is not None:
                os.close(current)

    def stop_accepting(self):
        if self.socket is not None:
            self.socket.close()

    def release(self):
        """Close handles only; stat followed by unlink cannot exclude another owner.

        Preserve the pathname after verified worker termination. A new runtime
        needs a generation-specific path or separately authorized owner retirement.
        """
        self.stop_accepting()
        for attribute in ("pin", "parent"):
            fd = self.__dict__.pop(attribute, None)
            if fd is not None:
                os.close(fd)
