"""Opt-in, content-free local evidence for ONE instrumented trace (Linux only).

No exporter, credentials, network, directory creation, cleanup or activation here.
A receipt is local SDK lifecycle evidence, never proof of backend delivery.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

MAX_OBSERVATIONS = 256
MAX_FILES = 256
MAX_BYTES = 65536
MAX_AGE = 86400
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")


def producer_identity():
    """PID + kernel start ticks + boot ID disambiguate PID reuse; never inherited env."""
    pid = os.getpid()
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", boot) or not fields[19].isdigit():
        raise ValueError("producer identity unavailable")
    return {"pid": pid, "start_ticks": int(fields[19]), "boot_id": boot}


def _private_directory(path):
    """Open every component without following symlinks; final directory is owned/private."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute private directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise ValueError("private directory required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _save(path, trace_id, document):
    """Exclusive final receipt; bounded nonblocking process-shared writer lock.

    Existing evidence is never replaced. A partial write stays invalid and blocks reuse.
    The owning activation plan must expire receipts; this function never deletes evidence.
    """
    import fcntl
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_BYTES or not _HEX32.fullmatch(trace_id):
        raise ValueError("receipt bounds")
    directory = _private_directory(path)
    lock = None
    try:
        lock = os.open(".writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        st = os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("invalid writer lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        names = os.listdir(directory)
        if len(names) >= MAX_FILES + 1:
            raise ValueError("receipt capacity reached")
        # Stop accumulating if the owner's retention job is not keeping up.
        now = time.time()
        for name in names:
            if name == ".writer.lock":
                continue
            st = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not _HEX32.fullmatch(name.removesuffix(".json")) or not name.endswith(".json") or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > MAX_BYTES or now - st.st_mtime > MAX_AGE:
                raise ValueError("receipt directory requires owner reconciliation")
        fd = os.open(trace_id + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(directory)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


class Receipt:
    """Fixed-size local lifecycle inventory, sealed once the root ends.

    Open/failed children, overflow, invalid IDs and late hooks prevent a valid terminal proof.
    No prompts, results, tool names, endpoints, profile paths or exception strings are saved.
    """
    def __init__(self, directory, trace_id, root_id, turn_id, producer=None):
        if not _HEX32.fullmatch(trace_id) or not _HEX16.fullmatch(root_id) or not isinstance(turn_id, str) or not turn_id or len(turn_id) > 1024:
            raise ValueError("invalid trace binding")
        self.directory = directory
        self.lock = threading.Lock()
        self.sealed = False
        self.invalid = False
        self.saved_digest = None
        self.saved_complete = False
        self.doc = {"schema": 1, "trace_id": trace_id, "root_id": root_id,
                    "turn_sha256": hashlib.sha256(turn_id.encode()).hexdigest(),
                    "producer": producer if producer is not None else producer_identity(),
                    "created_at": time.time(), "observations": {root_id: {"parent_id": None, "ended": False}}}

    def invalidate(self):
        """One lock-protected path; validity never depends on a later filesystem write."""
        with self.lock:
            self.invalid = True

    def terminal_proof(self):
        """Called by the owning collector AFTER independently verified turn quiescence.

        The caller must retain this exact Receipt object until that boundary. No persisted
        receipt or process-death inference substitutes for this fresh in-memory response.
        This function does not establish quiescence and does not freeze future events.
        """
        with self.lock:
            return {"receipt_sha256": self.saved_digest,
                    "valid": bool(self.sealed and self.saved_complete and not self.invalid
                                  and self.saved_digest and producer_identity() == self.doc["producer"]),
                    "producer": dict(self.doc["producer"]), "issued_at": time.time()}

    def started(self, observation_id):
        with self.lock:
            if self.sealed:
                self.invalid = True
                return
            obs = self.doc["observations"]
            if not isinstance(observation_id, str) or not _HEX16.fullmatch(observation_id) or observation_id in obs or len(obs) >= MAX_OBSERVATIONS:
                self.invalid = True
                return
            obs[observation_id] = {"parent_id": self.doc["root_id"], "ended": False}

    def ended(self, observation_id):
        with self.lock:
            if self.sealed or observation_id not in self.doc["observations"]:
                self.invalid = True
                return
            self.doc["observations"][observation_id]["ended"] = True

    def finish(self, reason="normal"):
        with self.lock:
            if self.sealed:
                return False
            self.sealed = True
            if reason not in {"normal", "eviction", "shutdown", "error"}:
                reason = "error"
            doc = dict(self.doc, sealed_at=time.time(), terminal_reason=reason,
                       inventory_valid=not self.invalid,
                       local_complete=(not self.invalid and reason == "normal" and all(x["ended"] for x in self.doc["observations"].values())))
            try:
                _save(self.directory, self.doc["trace_id"], doc)
                self.saved_digest = _digest(doc)
                self.saved_complete = doc["local_complete"]
                return True
            except Exception:
                return False  # Missing/partial receipt is UNKNOWN to the reader, never PASS.


def _digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def reconcile(receipt, backend, *, terminal_proof=None, now=None):
    """Validate an already private, complete backend observation envelope; never query remotely.

    This verifies the receipt's captured inventory only, not hooks lost before instrumentation.
    No missing/partial/expired evidence is interpreted as success.
    """
    now = time.time() if now is None else now
    try:
        if type(receipt["schema"]) is not int or receipt["schema"] != 1 or receipt["inventory_valid"] is not True or receipt["local_complete"] is not True or receipt["terminal_reason"] != "normal":
            return "unverified"
        created, sealed = receipt["created_at"], receipt["sealed_at"]
        if type(created) not in (int, float) or type(sealed) not in (int, float) or not 0 <= now - created <= MAX_AGE or not created <= sealed <= now:
            return "unverified"
        p = receipt["producer"]
        if type(p["pid"]) is not int or p["pid"] <= 0 or type(p["start_ticks"]) is not int or p["start_ticks"] <= 0 or not re.fullmatch(r"[0-9a-f-]{36}", p["boot_id"]):
            return "unverified"
        if not isinstance(terminal_proof, dict) or terminal_proof.get("valid") is not True or terminal_proof.get("receipt_sha256") != _digest(receipt) or terminal_proof.get("producer") != p:
            return "unverified"
        issued = terminal_proof.get("issued_at")
        if type(issued) not in (int, float) or not sealed <= issued <= now:
            return "unverified"
        tid, root = receipt["trace_id"], receipt["root_id"]
        if not _HEX32.fullmatch(tid) or not _HEX16.fullmatch(root) or not re.fullmatch(r"[0-9a-f]{64}", receipt["turn_sha256"]):
            return "unverified"
        expected = receipt["observations"]
        if not isinstance(expected, dict) or not 1 <= len(expected) <= MAX_OBSERVATIONS or root not in expected:
            return "unverified"
        for oid, row in expected.items():
            if not _HEX16.fullmatch(oid) or row["ended"] is not True or row["parent_id"] != (None if oid == root else root):
                return "unverified"
        if backend["producer_terminal_verified"] is not True or backend["local_receipt_current"] is not True or backend["complete"] is not True or backend["trace_id"] != tid or not isinstance(backend["observations"], list) or len(backend["observations"]) > MAX_OBSERVATIONS:
            return "unverified"
        seen = {}
        for row in backend["observations"]:
            oid = row["id"]
            if oid in seen or row["trace_id"] != tid or row["ended"] is not True:
                return "unverified"
            seen[oid] = row["parent_id"]
        if seen != {oid: row["parent_id"] for oid, row in expected.items()}:
            return "mismatch"
        return "captured_inventory_delivered"
    except (KeyError, TypeError, ValueError, AttributeError):
        return "unverified"


def read_receipt(directory, trace_id):
    """Read the immutable snapshot. It is provisional without a fresh producer validity proof."""
    if not _HEX32.fullmatch(trace_id):
        raise ValueError("invalid trace")
    folder = _private_directory(directory)
    try:
        fd = os.open(trace_id + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > MAX_BYTES:
                raise ValueError("invalid receipt")
            return json.loads(f.read(MAX_BYTES + 1))
    finally:
        os.close(folder)
