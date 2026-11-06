"""Request-bound local proof protocol. An authenticated transfer is not backend delivery."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

from .backend_readback import _invalid_constant, _unique_object
from .delivery_verification import _binding_pins

MAX_REQUEST = 8192
MAX_RESPONSE = 131072
MAX_REQUESTS = 256
_AGE = 30.0
_SKEW = 5.0
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_BASE = {"profile", "producer", "trace_id", "turn_sha256", "receipt_sha256"}
_FULL = _BASE | {"registration_sha256"}
_REQUEST = {"schema", "kind", "operation", "request_id", "issued_at", "binding"}
_RESPONSE = _REQUEST | {"request_sha256", "status", "envelope"}
_UNVERIFIED = b'{"status":"unverified"}'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _key(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("proof channel requires a 32-byte key")
    return value


def _binding(value, operation):
    required = _BASE if operation == "describe" else _FULL
    if operation not in {"describe", "transfer"} or not isinstance(value, dict) or set(value) != required:
        raise ValueError("invalid proof request binding")
    checked = _binding_pins(dict(value, registration_sha256=value.get("registration_sha256", "0" * 64)))
    return {key: checked[key] for key in required}


def _sign(payload, key):
    signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return _canonical(dict(payload, signature=signature))


def _decode(wire, key, maximum, kind, keys):
    if not isinstance(wire, bytes) or not 0 < len(wire) <= maximum:
        raise ValueError("invalid proof frame")
    value = json.loads(wire, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(value, dict) or set(value) != keys | {"signature"}:
        raise ValueError("invalid proof frame")
    signature = value.pop("signature")
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["kind"] != kind
            or not isinstance(signature, str) or not _HEX64.fullmatch(signature)):
        raise ValueError("invalid proof frame")
    expected = hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("unauthenticated proof frame")
    return value


def _fresh(issued, now):
    return (type(issued) in (float, int) and math.isfinite(issued) and issued >= 0
            and type(now) in (float, int) and math.isfinite(now)
            and now - _AGE <= issued <= now + _SKEW)


@dataclass(frozen=True)
class ProofReply:
    status: str
    _binding_wire: bytes = field(repr=False)
    envelope: bytes | None = field(repr=False)

    @property
    def binding(self):
        return json.loads(self._binding_wire)


class ProofAuthority:
    """One producer/profile, no reply cache, finite request admission and permanent death latch."""

    def __init__(self, key, *, profile, producer, handler, key_valid, clock=time.time):
        self._key = _key(key)
        self._profile, self._producer = profile, dict(producer)
        self._handler, self._key_valid, self._clock = handler, key_valid, clock
        self._pid, self._dead = os.getpid(), False
        self._seen, self._lock = set(), threading.Lock()

    def close(self):
        self._dead = True

    def _valid(self):
        if os.getpid() != self._pid or self._dead:
            return False
        try:
            if self._key_valid() is True:
                return not self._dead and os.getpid() == self._pid
        except Exception:
            pass  # arbitrary filesystem/lifecycle errors carry no output authority
        self._dead = True
        return False

    @property
    def active(self):
        return not self._dead and os.getpid() == self._pid

    def process(self, wire):
        if not self._valid():
            return _UNVERIFIED
        try:
            request = _decode(wire, self._key, MAX_REQUEST, "receipt_proof_request", _REQUEST)
            identity = request["request_id"]
            binding = _binding(request["binding"], request["operation"])
            if (not isinstance(identity, str) or not _HEX32.fullmatch(identity)
                    or not _fresh(request["issued_at"], self._clock())
                    or binding["profile"] != self._profile or binding["producer"] != self._producer):
                return _UNVERIFIED
            with self._lock:
                if identity in self._seen or len(self._seen) >= MAX_REQUESTS:
                    return _UNVERIFIED
                self._seen.add(identity)
            result = self._handler(request["operation"], binding)
            response = self._response(request, binding, result)
            encoded = _sign(response, self._key)
            # A close, key change or observed abandonment during the handler
            # permanently discards its response, even if the transfer was issued.
            if len(encoded) > MAX_RESPONSE or not self._valid():
                return _UNVERIFIED
            return encoded
        except Exception:
            # This is an untrusted wire/handler boundary: no exception text,
            # partial reply or failure cache may become proof authority.
            return _UNVERIFIED

    def _response(self, request, binding, result):
        if not isinstance(result, dict) or set(result) != {"binding", "envelope"}:
            raise ValueError("proof unavailable")
        full = _binding(result["binding"], "transfer")
        if any(full[key] != value for key, value in binding.items()):
            raise ValueError("proof identity changed")
        envelope = result["envelope"]
        describe = request["operation"] == "describe"
        if (describe and envelope is not None) or (not describe and not isinstance(envelope, dict)):
            raise ValueError("proof unavailable")
        if not describe and any(envelope.get(key) != value for key, value in full.items()):
            raise ValueError("transfer identity changed")
        return dict(request, kind="receipt_proof_reply", binding=full,
                    issued_at=self._clock(), request_sha256=hashlib.sha256(_canonical(request)).hexdigest(),
                    status="ready" if describe else "transferred", envelope=envelope)


class ProofClient:
    """One pending operation per consumer; every accept attempt consumes it, including failure."""

    def __init__(self, key, *, clock=time.time):
        self._key, self._clock = _key(key), clock
        self._pid, self._closed = os.getpid(), False
        self._pending, self._issued, self._lock = None, 0, threading.Lock()

    def begin(self, operation, binding):
        if os.getpid() != self._pid or self._closed:
            raise RuntimeError("proof consumer closed")
        normalized = _binding(binding, operation)
        with self._lock:
            if self._closed or self._pending is not None or self._issued >= MAX_REQUESTS:
                raise RuntimeError("proof consumer request capacity")
            request = {"schema": 1, "kind": "receipt_proof_request", "operation": operation,
                       "binding": normalized, "request_id": secrets.token_hex(16),
                       "issued_at": self._clock()}
            wire = _sign(request, self._key)
            if len(wire) > MAX_REQUEST:
                raise ValueError("proof request exceeds frame bound")
            self._pending = request
            self._issued += 1
            return wire

    def accept(self, wire):
        if os.getpid() != self._pid or self._closed:
            return None  # reject fork copies before an inherited lock can block
        with self._lock:
            pending, self._pending = self._pending, None
        if pending is None:
            return None
        try:
            reply = _decode(wire, self._key, MAX_RESPONSE, "receipt_proof_reply", _RESPONSE)
            if (not _fresh(pending["issued_at"], self._clock())
                    or not _fresh(reply["issued_at"], self._clock())
                    or reply["operation"] != pending["operation"]
                    or reply["request_id"] != pending["request_id"]
                    or reply["request_sha256"] != hashlib.sha256(_canonical(pending)).hexdigest()):
                return None
            full = _binding(reply["binding"], "transfer")
            if any(full[key] != value for key, value in pending["binding"].items()):
                return None
            envelope = reply["envelope"]
            if pending["operation"] == "describe":
                if reply["status"] != "ready" or envelope is not None:
                    return None
                return None if self._closed else ProofReply("ready", _canonical(full), None)
            if (reply["status"] != "transferred" or not isinstance(envelope, dict)
                    or any(envelope.get(key) != value for key, value in full.items())):
                return None
            return None if self._closed else ProofReply("transferred", _canonical(full), _canonical(envelope))
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            return None

    def close(self):
        self._closed = True
        if os.getpid() == self._pid:
            with self._lock:
                self._pending = None
