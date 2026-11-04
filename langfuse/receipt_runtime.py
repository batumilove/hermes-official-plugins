"""Opt-in local Receipt ownership tied to the host turn; no transport or exporter."""
from __future__ import annotations

import os
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

    def _settings(self):
        settings = self.context.get_config("receipts", {})
        if not isinstance(settings, dict) or settings.get("enabled") is not True:
            return None
        directory = settings.get("directory")
        if not isinstance(directory, str) or not os.path.isabs(directory):
            return None
        return directory

    def open_trace(self, trace_id, root_id, turn_id):
        if os.getpid() != self.pid:
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
            self._expire()
            item = self.turns.get(key)
            if item is None:
                if len(self.turns) >= _MAX_TURNS:
                    return None
                collector = TurnEvidenceCollector(
                    self.context._manager, self.context, delivery_receipts,
                    turn_id=turn_id, receipt_directory=directory)
                collector.attach_current_turn()
                item = (self.clock(), collector)
                self.turns[key] = item
            collector = item[1]
            receipt = collector.open_trace(trace_id, root_id)
            if receipt is None:
                return None
            if collector.retain(trace_id) is None:
                receipt.invalidate()
                return None
            return receipt

    def collect(self, turn_id, *, deadline_seconds=1.0):
        """Local status/proof report only; never claims backend delivery or sends data."""
        if os.getpid() != self.pid:
            return {"status": "unverified"}
        directory = self._settings()
        if directory is None:
            return {"status": "unverified"}
        with self.lock:
            self._expire()
            matches = [c for (d, _), (_, c) in self.turns.items()
                       if d == directory and c.turn_id == turn_id
                       and c.profile == self.context._manager.scope_key]
        if len(matches) != 1:
            return {"status": "unverified"}
        return matches[0].collect(deadline_seconds=deadline_seconds)

    def _expire(self):
        now = self.clock()
        for key, (opened, _) in list(self.turns.items()):
            if now - opened >= _RETENTION_SECONDS:
                del self.turns[key]
