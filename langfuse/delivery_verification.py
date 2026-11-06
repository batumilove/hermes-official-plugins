"""One-shot authenticated proof consumption followed by independent backend readback."""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass

from . import delivery_receipts as receipts
from .backend_readback import ObservationReader, ReadbackError, _invalid_constant, _unique_object

_WIRE_BYTES = 128 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TRACE = re.compile(r"[0-9a-f]{32}")


def _binding_pins(binding):
    if not isinstance(binding, dict):
        raise ValueError("invalid binding")
    profile = binding.get("profile")
    if (not isinstance(profile, str) or not profile.strip() or len(profile) > 4096
            or any(ord(c) < 32 for c in profile)):
        raise ValueError("invalid profile pin")
    for field, pattern in (("trace_id", _TRACE), ("turn_sha256", _SHA256),
                           ("receipt_sha256", _SHA256), ("registration_sha256", _SHA256)):
        if not isinstance(binding.get(field), str) or not pattern.fullmatch(binding[field]):
            raise ValueError("invalid identity pin")
    producer = binding.get("producer")
    if not isinstance(producer, dict):
        raise ValueError("invalid producer pin")
    for field in ("pid", "start_ticks"):
        if type(producer.get(field)) is not int or producer[field] <= 0:
            raise ValueError("invalid producer pin")
    boot = producer.get("boot_id")
    if not isinstance(boot, str) or str(uuid.UUID(boot)) != boot:
        raise ValueError("invalid producer pin")
    return {"profile": profile, "producer": {"pid": producer["pid"],
            "start_ticks": producer["start_ticks"], "boot_id": boot},
            **{field: binding[field] for field in ("trace_id", "turn_sha256",
                                                  "receipt_sha256", "registration_sha256")}}


@dataclass(frozen=True)
class DeliveryCheck:
    verdict: str
    reason: str
    pages: int = 0
    expected_count: int = 0
    observed_count: int = 0


def _local_envelope(payload):
    """Validate local proof mechanics first; this internal check makes no delivery claim."""
    snapshot = payload["snapshot"]
    if (snapshot["trace_id"] != payload["trace_id"]
            or snapshot["turn_sha256"] != payload["turn_sha256"]
            or snapshot["producer"] != payload["producer"]):
        raise ValueError("inconsistent signed identity")
    return {"trace_id": snapshot["trace_id"], "complete": True,
            "producer_terminal_verified": True, "local_receipt_current": True,
            "observations": [dict(row, id=oid, trace_id=snapshot["trace_id"])
                             for oid, row in snapshot["observations"].items()]}


class DeliveryVerifier:
    """A bounded consumer lifetime with one-use nonces, not a persistent replay store.

    The owner must authenticate transport and independently pin producer/profile,
    turn, trace, receipt and registration digests. Never reconstruct those pins
    from an untrusted envelope. Retain this instance for the entire acceptance
    attempt; restarting it loses replay history and is not a retry allowance.
    """

    def __init__(self, key: bytes, reader: ObservationReader, *, freshness_seconds=120.0,
                 clock=time.time):
        from hermes_cli.plugins_turn_evidence_collector import TransferVerifier

        self._verifier = TransferVerifier(key, freshness_seconds=freshness_seconds, clock=clock)
        self._reader = reader
        self._clock = clock

    def verify(self, wire: bytes, *, expected_binding: dict) -> DeliveryCheck:
        """Consume exact wire bytes once; errors are fixed codes with no private output."""
        if not isinstance(wire, bytes) or not 0 < len(wire) <= _WIRE_BYTES:
            return DeliveryCheck("unverified", "invalid_transfer")
        # The core supports optional pins for offline consumers. Live readback
        # requires both digests, so a weaker caller binding cannot enable queries.
        try:
            pins = _binding_pins(expected_binding)
        except (ValueError, TypeError):
            return DeliveryCheck("unverified", "invalid_binding")
        try:
            # Owned decoded bytes prevent caller mutation during a backend request.
            envelope = json.loads(wire, object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
            payload = self._verifier.verify(envelope, expected_binding=pins)
            if payload is None:
                return DeliveryCheck("unverified", "invalid_transfer")
            local = _local_envelope(payload)
            if receipts.reconcile(payload["snapshot"], local,
                                  terminal_proof=payload["proof"], now=self._clock()) != "captured_inventory_delivered":
                return DeliveryCheck("unverified", "invalid_local_evidence")
            snapshot = payload["snapshot"]
            # Receipt creation follows root creation. The fixed five-second margin
            # covers that ordering; every returned start/end must fit this window.
            readback = self._reader.read(payload["trace_id"],
                                         start_time=snapshot["created_at"] - 5,
                                         end_time=snapshot["sealed_at"] + 5)
            backend = dict(local, observations=list(readback.observations), complete=readback.complete)
            verdict = receipts.reconcile(snapshot, backend, terminal_proof=payload["proof"], now=self._clock())
            return DeliveryCheck(verdict, "inventory_match" if verdict == "captured_inventory_delivered"
                                 else "inventory_not_delivered", pages=readback.pages,
                                 expected_count=len(snapshot["observations"]),
                                 observed_count=len(backend["observations"]))
        except ReadbackError as error:
            return DeliveryCheck("unverified", str(error))
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError, OverflowError):
            return DeliveryCheck("unverified", "invalid_transfer")
