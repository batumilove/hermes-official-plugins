"""Single selected local acceptance attempt: fresh collector request, then independent HTTPS readback."""
from __future__ import annotations

import os
import threading

from .delivery_verification import DeliveryCheck, DeliveryVerifier
from .proof_paths import PrivateKey
from .proof_socket import exchange
from .proof_wire import ProofClient


class LiveDeliveryAttempt:
    """One attempt, one selected Receipt, no retry or saved-proof input.

    Run as the producer's OS owner on its Linux host. Profile/producer/turn/trace
    and Receipt digest come from the operator's independent private records.
    Only the fixed DeliveryCheck may leave that private controller process.
    """

    def __init__(self, *, socket_path, key_file, reader):
        self._pid, self._closed, self._used = os.getpid(), False, False
        self._lock = threading.Lock()
        self._key = PrivateKey(key_file)
        try:
            self._client = ProofClient(self._key.value)
            self._verifier = DeliveryVerifier(self._key.value, reader)
        except BaseException:
            self._key.close()
            raise
        self._socket_path = socket_path

    def _active(self):
        return not self._closed and os.getpid() == self._pid and self._key.valid()

    def verify(self, *, expected_binding):
        if os.getpid() != self._pid or self._closed:
            return DeliveryCheck("unverified", "attempt_closed")
        with self._lock:
            if self._used or self._closed:
                return DeliveryCheck("unverified", "attempt_consumed")
            self._used = True
        try:
            if not self._active():
                return DeliveryCheck("unverified", "proof_key_unavailable")
            request = self._client.begin("describe", expected_binding)
            ready = self._client.accept(exchange(self._socket_path, request))
            if ready is None or not self._active():
                return DeliveryCheck("unverified", "proof_unavailable")
            request = self._client.begin("transfer", ready.binding)
            sent = self._client.accept(exchange(self._socket_path, request))
            if sent is None or not self._active():
                return DeliveryCheck("unverified", "proof_unavailable")
            result = self._verifier.verify(sent.envelope, expected_binding=ready.binding)
            return result if self._active() else DeliveryCheck("unverified", "attempt_closed")
        except (OSError, ValueError, RuntimeError, TypeError):
            return DeliveryCheck("unverified", "proof_unavailable")

    def close(self):
        self._closed = True
        self._client.close()
        self._key.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
