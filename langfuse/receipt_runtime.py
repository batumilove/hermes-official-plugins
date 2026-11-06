"""Opt-in Receipt ownership and request-bound proof channel tied to the host turn."""
from __future__ import annotations

import os
import atexit
import threading
import time
from collections import OrderedDict

_MAX_TURNS = 16
_RETENTION_SECONDS = 300.0


class ReceiptRuntime:
    """Bounded owner retained beyond SDK trace teardown, polled explicitly after turn exit."""

    def __init__(self, context, *, clock=time.monotonic):
        self.context = context
        self.clock = clock
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.turns = OrderedDict()
        self.closed = False
        self.channel = None
        self._channel_attempted = False
        self._channel_spec = None
        self._at_exit = False
        # Register while the host owns plugin setup, before a turn/runtime lock.
        # Older hosts may collect locally but cannot enable a listener without cleanup.
        cleanup = getattr(context, "on_unload", None)
        self._cleanup_handle = cleanup(self.close) if callable(cleanup) else None

    def _settings(self):
        settings = self.context.get_config("receipts", {})
        if not isinstance(settings, dict) or settings.get("enabled") is not True:
            return None
        directory = settings.get("directory")
        if not isinstance(directory, str) or not os.path.isabs(directory):
            return None
        return directory

    def open_trace(self, trace_id, root_id, turn_id):
        if os.getpid() != self.pid or self.closed:
            return None
        directory = self._settings()
        if directory is None:
            return None
        from hermes_cli.plugins_turn_evidence_collector import TurnEvidenceCollector
        from hermes_cli import plugins_turn_boundary as boundary
        from . import delivery_receipts

        scope = boundary._CURRENT.get()
        if scope is None or scope.turn_id != turn_id:
            return None
        # Exact boundary identity prevents same turn text across overlapping calls
        # from sharing custody. The collector checks manager, profile and generation.
        key = (directory, scope)
        with self.lock:
            if self.closed:
                return None
            channel_key = self._ensure_channel(directory)
            if channel_key is False:
                return None
            _retired = self._expire()
            item = self.turns.get(key)
            if item is None:
                if len(self.turns) >= _MAX_TURNS:
                    return None
                collector = TurnEvidenceCollector(
                    self.context._manager, self.context, delivery_receipts,
                    turn_id=turn_id, receipt_directory=directory, key=channel_key)
                collector.attach_current_turn()
                item = (self.clock(), collector)
                self.turns[key] = item
            collector = item[1]
        # A copied boundary can revisit a collector whose storage lock is busy.
        # Never let that wait restore a convoy behind the global runtime lock.
        receipt = collector.open_trace(trace_id, root_id)
        if receipt is None:
            return None
        retained = collector.retain(trace_id) is not None
        with self.lock:
            _retired.extend(self._expire())
            admitted = (retained and not self.closed and self.turns.get(key) is item
                        and self._settings() == directory)
        if not admitted:
            receipt.invalidate()
            return None
        return receipt

    def collect(self, turn_id, *, deadline_seconds=1.0):
        """Local status/proof report only; never claims backend delivery or sends data."""
        if os.getpid() != self.pid or self.closed:
            return {"status": "unverified"}
        directory = self._settings()
        if directory is None:
            return {"status": "unverified"}
        with self.lock:
            _retired = self._expire()
            matches = [c for (d, _), (_, c) in self.turns.items()
                       if d == directory and c.turn_id == turn_id
                       and c.profile == self.context._manager.scope_key]
        if len(matches) != 1:
            return {"status": "unverified"}
        return matches[0].collect(deadline_seconds=deadline_seconds)

    def _expire(self):
        """Caller holds lock; keep removals alive until that caller releases it."""
        now = self.clock()
        retired = []
        for key, (opened, _) in list(self.turns.items()):
            if now - opened >= _RETENTION_SECONDS:
                retired.append(self.turns.pop(key))
        return retired

    def _proof_config(self, directory):
        settings = self.context.get_config("receipts", {})
        channel = settings.get("proof_channel", {}) if isinstance(settings, dict) else {}
        if not isinstance(channel, dict) or channel.get("enabled") is not True:
            return None
        socket_path, key_path = channel.get("socket"), channel.get("key_file")
        if not all(isinstance(p, str) and os.path.isabs(p) for p in (socket_path, key_path)):
            raise ValueError("absolute proof paths required")
        if any(os.path.commonpath((os.path.normpath(os.path.dirname(p)), os.path.normpath(directory)))
               == os.path.normpath(directory)
               for p in (socket_path, key_path)):
            raise ValueError("proof state requires a separate private directory")
        return (directory, socket_path, key_path)

    def _channel_enabled(self):
        return (not self.closed and os.getpid() == self.pid
                and self._cleanup_handle is not None and self._cleanup_handle.active is True
                and self._settings() is not None
                and self._proof_config(self._settings()) == self._channel_spec)

    def _ensure_channel(self, directory):
        spec = self._proof_config(directory)
        if spec is None:
            return None if not self._channel_attempted else False
        if self._channel_attempted:
            return (self.channel.key if self.channel is not None and self.channel.active
                    and self._channel_enabled() else False)
        self._channel_attempted, self._channel_spec = True, spec
        if self._cleanup_handle is None or self._cleanup_handle.active is not True:
            return False
        from .delivery_receipts import producer_identity
        from .proof_socket import ProofServer
        try:
            self.channel = ProofServer(spec[1], spec[2], profile=self.context._manager.scope_key,
                                       producer=producer_identity(), handler=self._proof_handler,
                                       enabled=self._channel_enabled)
        except (OSError, ValueError):
            return False  # SDK tracing stays fail-open; this receipt has no authority
        atexit.register(self.close)
        self._at_exit = True
        return self.channel.key if self.channel.active else False

    def _proof_handler(self, operation, binding):
        if not self._channel_enabled() or not self.lock.acquire(timeout=0.1):
            return None
        _retired = []
        try:
            _retired.extend(self._expire())
            matches = self._proof_matches(binding)
        finally:
            self.lock.release()
        if len(matches) != 1:
            return None
        key, item = matches[0]
        collector = item[1]
        trace = binding["trace_id"]
        report = collector.collect(deadline_seconds=0.2)
        if report.get(trace, {}).get("status") != "collected":
            return None
        expected = collector.expected_binding(trace)
        if any(expected.get(k) != v for k, v in binding.items()):
            return None
        if not self.lock.acquire(timeout=0.1):
            return None
        try:
            _retired.extend(self._expire())
            if not self._owns_proof_collector(key, item, binding) or not self._channel_enabled():
                return None
        finally:
            self.lock.release()
        # Collector storage and locking may stall. Never carry that latency into
        # admission of unrelated turns or runtime shutdown. The result has no
        # authority to leave this handler until ownership is revalidated below.
        envelope = collector.issue_transfer(trace) if operation == "transfer" else None
        if not self.lock.acquire(timeout=0.1):
            return None
        try:
            _retired.extend(self._expire())
            if not self._owns_proof_collector(key, item, binding) or not self._channel_enabled():
                return None
            return {"binding": expected, "envelope": envelope}
        finally:
            self.lock.release()

    def _proof_matches(self, binding):
        # Caller holds the runtime lock and has expired its current ledger.
        return [(key, item) for key, item in self.turns.items()
                if key[0] == self._channel_spec[0] and item[1].profile == binding["profile"]
                and item[1].producer == binding["producer"]
                and item[1].turn_sha256 == binding["turn_sha256"]]

    def _owns_proof_collector(self, key, item, binding):
        return self.turns.get(key) is item and len(self._proof_matches(binding)) == 1

    def close(self):
        if os.getpid() != self.pid:
            if self.channel is not None:
                self.channel.close()
            return
        with self.lock:
            self.closed = True
            channel = self.channel
        # The worker can be waiting for the runtime lock: never join while holding it.
        stopped = channel is None or channel.close()
        if stopped and self._at_exit:
            atexit.unregister(self.close)
            self._at_exit = False
